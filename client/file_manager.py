import pefile
import binascii
import win32api
from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
import hashlib
import lief
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates,load_pem_pkcs7_certificates

#Pegar informações básicas de cada binário:
    # Certificado:
        # Ver se é válido
        # Certificate chain e detalhes (issuer, etc.)
    # Nome
    # Versão


'''Dado desejado:

Arquivo:
	infos:
		name: chrome
		version: 1.0w
		publisher: whatever
	signature:
		pe_hash: aaaa
		signature: bbbb
		full_chain:
			-blabla:
			-blabla2:
		valid_from: 1/1/1
		valid_until: 1/1/1

Isso permite que o servidor faça a verificação da assinatura do lado dele, mas sem receber o arquivo completo.

infos, foda-se.
'''

def get_file_properties(fname):
    """
    Reads all properties of the given file return them as a dictionary.
    """
    propNames = ('Comments', 'InternalName', 'ProductName',
                'CompanyName', 'LegalCopyright', 'ProductVersion',
                'FileDescription', 'LegalTrademarks', 'PrivateBuild',
                'FileVersion', 'OriginalFilename', 'SpecialBuild')

    props = {'FixedFileInfo': None, 'StringFileInfo': None, 'FileVersion': None}

    try:
        # backslash as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc
        fixedInfo = win32api.GetFileVersionInfo(fname, '\\')
        props['FixedFileInfo'] = fixedInfo
        props['FileVersion'] = "%d.%d.%d.%d" % (fixedInfo['FileVersionMS'] / 65536,
                                                fixedInfo['FileVersionMS'] % 65536, 
                                                fixedInfo['FileVersionLS'] / 65536,
                                                fixedInfo['FileVersionLS'] % 65536)

        # \VarFileInfo\Translation returns list of available (language, codepage)
        # pairs that can be used to retreive string info. We are using only the first pair.
        lang, codepage = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')[0]

        # any other must be of the form \StringfileInfo\%04X%04X\parm_name, middle
        # two are language/codepage pair returned from above

        strInfo = {}
        for propName in propNames:
            strInfoPath = u'\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, propName)
            ## print str_info
            strInfo[propName] = win32api.GetFileVersionInfo(fname, strInfoPath)

        props['StringFileInfo'] = strInfo
    except:
        pass

    return props


def extract_signature_info(file_path):
    try:
        pe = pefile.PE(file_path)

        info = pe.VS_FIXEDFILEINFO[0]
        version_info = pe.VS_VERSIONINFO[0]
        print(info)
        print(version_info)

        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size

        if address == 0:
            print('Error: source file not signed')
            return
        
        signature = bytes(pe.write()[address+8:])

        # Attempt to load as PKCS7 (P7B)
        try:
            pkcs7 = load_der_pkcs7_certificates(signature)
        except ValueError:
            # If DER fails, try PEM
            pkcs7 = load_pem_pkcs7_certificates(signature)

        certificates = []
        for cert in pkcs7:
            certificates.append(cert)

        certificate_data = []
        for cert in certificates:
            cert: x509.Certificate = cert
            certificate_data.append({
                "subject": cert.subject,
                "issuer": cert.issuer,
                "version": cert.version,
                "notvalidbefore": cert.not_valid_before_utc,
                "notvalidafter": cert.not_valid_after_utc,
                "signature": {cert.signature},
            })
            
        return certificate_data

    except pefile.PEFormatError:
        print(f"Error: {file_path} is not a valid PE file.")
    except Exception as e:
        print(f"An error occurred: {e}")

def extract_signature_info_signify(file_path):
    with open(file_path, "rb") as f:
        signed_file = AuthenticodeFile.from_stream(f)
        for signed_data in signed_file.signatures:
            #print(vars(signed_data))
            #print(vars(signed_data.certificates))

            for certificate in signed_data.certificates:
                print(certificate.verify)

            print(signed_data.explain_verify())

def extract_signature_info_lief(file_path):
    try:
        binary = lief.PE.parse(file_path)
        if binary:
            if binary.has_signatures:
                for signature in binary.signatures:
                    print(signature)
                    if signature.check():
                        print("Signature is valid.")
                    else:
                        print("Signature is invalid.")
            else:
                print("No signatures found in the PE file.")
        else:
            print("Could not parse the PE file.")

    except lief.bad_file as e:
        print(f"Error parsing PE file: {e}")
    except FileNotFoundError:
        print("File not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def get_pe_hash(file_path):
    with open(file_path, "rb") as f:
        signed_file = AuthenticodeFile.from_stream(f)

        # Get the PE hash (digest of the file content that is signed)
        # The hash algorithm used in the signature can be found in signed_file.signed_data.digest_algorithm
        # You can calculate the hash of the file content yourself using a library like hashlib,
        # but signify handles the relevant parts for signature verification.
        # The actual hash value used for verification is part of the signature structure.
        # You can access details of the signature if needed, for instance:
        # print(f"Digest Algorithm: {signed_file.signed_data.digest_algorithm.name}")
        # print(f"Digest: {signed_file.signed_data.digest.hex()}")

        for signature in signed_file.signatures:
            print(signature.get_content_digest())

def verify_pe_signature(file_path):
    try:
        with open(file_path, "rb") as f:
            signed_file = AuthenticodeFile.from_stream(f)
            status, err = signed_file.explain_verify()


            if status == AuthenticodeVerificationResult.OK:
                print(f"Signature of '{file_path}' is valid.")
            else:
                print(f"Signature of '{file_path}' is invalid: {err}")

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred during verification: {e}")



# Example usage:
# Replace 'path/to/your/signed_executable.exe' with the actual path

FILEPATH = r'C:\Program Files\Google\Chrome\Application\Chrome.exe'
extract_signature_info_lief(FILEPATH)

"""
certificate_data = extract_signature_info(FILEPATH)
properties = get_file_properties(FILEPATH)

#print(certificate_data)
print(properties)

hash = get_pe_hash(FILEPATH)
verify_pe_signature(FILEPATH)
"""

print("\n\n\n\n\n")