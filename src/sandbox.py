from src.ACCOUNTutils import *
mnemonic = 'plastic bubble oxygen club sort vivid tone session party enjoy team nation'
account = Account(mnemonic=mnemonic, root_path="m/45'/0/0/0", address_path="m/45'/0")
account.spillMnemonic()
account.spillXPRV()
account.spillXPUB()
account.spillAddresses()