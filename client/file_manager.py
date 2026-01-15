import win32api
import lief
import json
from pathlib import Path

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

def extract_signature_info_lief(file_path):
    pe = lief.parse(file_path)
    pe_signature_data = []
    if len(pe.signatures):
        for signature in pe.signatures:
            signature_data = {}
            signature_data["general"] = str(signature)
            #print(signature.check())
            signature_data["hash"] = str(signature.content_info.digest.hex())
            
            signature_data["certificates"] = []
            for crt in signature.certificates:
                certificate_data = {}
                certificate_data["issuer"] = crt.issuer
                certificate_data["subject"] = crt.subject
                certificate_data["signature_algorithm"] = crt.signature_algorithm
                certificate_data["signature"] = crt.signature.hex()
                certificate_data["valid_from"] = crt.valid_from
                certificate_data["valid_to"] = crt.valid_to
                signature_data["certificates"].append(certificate_data)

            signature_data["raw_data"] = str(signature.raw_der.hex())

            pe_signature_data.append(signature_data)
            #print(signature.signers[0]) #Not useful, i guess

            #Read it back and check it
            #detached_sig = lief.PE.Signature.parse("lief_signature.p7b")
            #print(pe.verify_signature(detached_sig))
    
    return pe_signature_data

def analyze_pe(FILEPATH: str):
    pe_data = {}

    pe_data["file_properties"] = get_file_properties(FILEPATH)
    pe_data["signatures"] = extract_signature_info_lief(FILEPATH)

    return pe_data

def check_submission(submission_path: str):
    #Load from JSON file/data
    #The server will load this differently.
    with open(submission_path, "r") as json_file:
        data = json.load(json_file)

    #Check if the hash is correct
    for signature in data["signatures"]:
        #Lief does not allow loading the signature from bytes, so we have to actually write to a file and then read from it. Stupid, I know.
        signature_bytes = bytes.fromhex(signature["raw_data"])
        Path("./temp_signature.p7b").write_bytes(signature_bytes)
        signature_data = lief.PE.Signature.parse("./temp_signature.p7b")

        #print(signature_data)
        if signature_data.check() == lief.PE.Signature.VERIFICATION_FLAGS.OK:
            print("Signature is valid!!")
            return True
        else:
            print("Signature is not valid.")
            return False

    return False 

if __name__ == "__main__": #Showcase
    FILEPATH = r'C:\Program Files\Google\Chrome\Application\chrome.exe'

    print("\n\n========= Processing file =============\n\n")

    pe_data = analyze_pe(FILEPATH)
    print(pe_data)

    with open("output.json", "w") as json_file:
        json.dump(pe_data, json_file, indent=4)

    print("\n\n========= CHECKING SUBMISSION ===========\n\n")

    check_submission("output.json")