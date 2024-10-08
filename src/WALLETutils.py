from src.ADDRESSutils import *

class Wallet:
    def __init__(self, seed, addressType, path, gapLimit):
        self.seed = seed
        self.addressType = addressType

        self.addressPaths = []

        self.addresses = []
        self.changeAddresses = []
        for addressNum in range(gapLimit):
            self.addressPaths.append(path+ '/'+str(addressNum))
        self.path = path

        self.addresses = []
        for i in range(gapLimit):
            self.addresses.append(Address(self.seed, self.addressPaths[i], self.addressType))