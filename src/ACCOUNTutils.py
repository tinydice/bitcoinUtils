from src.WALLETutils import *
from src.BIP32utils import *
from src.BIP39utils import *
from src.COLORutils import *

class Account:
    def __init__(self, mnemonic="", root_path="", address_path="",passphrase=""):

        self.mnemonic = mnemonic
        self.root_path = root_path
        self.address_path = address_path
        self.passphrase = passphrase

        self.word_count = len(self.mnemonic.split(' '))
        self.entropyHash = mnemonic_to_entropyHash(self.mnemonic)

        self.wallets = []

        self.addressType = 'P2PKH'

        self.seed = get_seed(self.mnemonic.encode('utf-8'), self.passphrase)
        self.root_xprv = extendedKey.parse_from_seed(self.seed)
        self.xprv = self.root_xprv.derive_child_xprv(convert_path(self.root_path))
        self.derived_addr_prv = self.root_xprv.derive_child_xprv(convert_path(self.root_path))
        self.xpub = self.derived_addr_prv.derive_pubkey()

        self.wallet = Wallet(self.root_xprv, self.addressType, self.address_path, 10)

    def spillMnemonic(self):
        if (self.passphrase != ''):
            print(f'Passphrase:')
            print(f"    {self.passphrase}")
        if (validate_mnemonic(self.mnemonic)):
            self.verifyResult = green("✔")
        else:
            self.verifyResult = red("X")
        print(f'Entropy:')
        print(f"    {blue(self.entropyHash.hex())}     {self.verifyResult}")
        print(f'Mnemonic:')
        print(f"    {green(self.mnemonic)} {self.passphrase}     {self.verifyResult}")
        self.verifyResult = green("✔") if (get_mnemonic(self.entropyHash, self.word_count) == self.mnemonic) else red("X")
        if (not validate_mnemonic(self.mnemonic)):
            print(f'    {red("ERROR: INVALID MNEMONIC")}')
    def spillXPRV(self):
        if (validate_mnemonic(self.mnemonic)):
            print(f'XPRV:')
            print(f"    {self.xprv.serialize()}")
        else:
            print(f'    {red("ERROR: INVALID XPRV")}')

    def spillXPUB(self):
        if (validate_mnemonic(self.mnemonic)):
            print(f'XPUB ({self.root_path}):')
            print(f"    {self.xpub.serialize()}")
        else:
            print(f'    {red("ERROR: INVALID XPUB")}')

    def spillAddresses(self):
        if (validate_mnemonic(self.mnemonic)):
            print(f'Addresses:        ')
            for address in self.wallet.addresses:
                address.spill_address(False)
        else:
            print(f'    {red("ERROR: INVALID ADDRESSES")}')