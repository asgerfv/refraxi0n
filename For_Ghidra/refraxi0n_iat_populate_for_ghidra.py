#Apply IAT dump file to Ghidra
#@author Asger Fris-Vigh
#@category Dynamic IAT Resolving on Windows
#@keybinding
#@menupath
#@toolbar
#@toolbar

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.app.cmd.data import *
from ghidra.program.model.data.DataUtilities import *



def main():

    try:
        fileObject = askFile('Select IAT file', 'Open')
    except:
        print('File could not be opened')
        quit()

    ProcessFile( fileObject.getPath() )



def CreateNewStructFromString(structDefinitionString) :
    dataTypeManager = currentProgram.getDataTypeManager()
    parser = CParser( dataTypeManager )

    newDataType = parser.parse(structDefinitionString)
    print("struct:", structDefinitionString)

    transaction = dataTypeManager.startTransaction("POPULATE_IAT")
    dataTypeManager.addDataType(newDataType, None)
    dataTypeManager.endTransaction(transaction, True)

    return newDataType


def Populate(ghidraListing, structMembers, currentReferences) :
    # Create a new structure with the labels so far
    if len(structMembers) and len(currentReferences) :

        # Build the struct definition string
        newStructName = GetStructNameFromIatName(structMembers[0])
        newStructString = "struct " + newStructName + " { "

        for currentStructLabel in structMembers :
            memberString = "void* " + currentStructLabel + "; "
            newStructString += memberString

        newStructString += " }; "
        newDataType = CreateNewStructFromString(newStructString)
        assert(newDataType != None)

        # Now create a type that's a pointer to the new struct
        newStructString = "typedef " + newStructName + "* " + newStructName + "Ptr_t ;"
        newDataType = CreateNewStructFromString(newStructString)
        assert(newDataType != None)

        # Apply the new Structure Type at the references memory location(s)
        for currentRef in currentReferences :
            ghidraAddress = toAddr(currentRef)
            existingGhidraDataAtLocation = ghidraListing.getDefinedDataAt(ghidraAddress)

            # Make sure the memory location is data and not code
            ghidraUnitCodeAtLocation = ghidraListing.getCodeUnitContaining(ghidraAddress)
            ghidraAddressOfPossibleOpcodeAtLocation = ghidraUnitCodeAtLocation.getMinAddress()
            if ghidraAddress == ghidraAddressOfPossibleOpcodeAtLocation :
                print(
                    "\tWill change data at "
                    + str(ghidraAddress)
                    + " from '"
                    + str(existingGhidraDataAtLocation)
                    + "' to '"
                    + str(newDataType)
                    + "')"
                    )
                ghidraListing.clearCodeUnits(ghidraAddress, toAddr(currentRef), True)
                ghidraListing.createData(ghidraAddress, newDataType)
            else :
                print(
                    "Will not apply new type to address as OPCODES were detected: '"
                     + str(ghidraUnitCodeAtLocation)
                     + "'. The label is still updated on "
                     + currentAddress
                     + " which should be enough to resolve its symbol in the disassembly."
                     )



# E.g.:
# IN : kernel32_SomeFunction
# OUT: IAT_Resolved__kernel32
def GetStructNameFromIatName(iatName) :
    dllName = iatName.split('_')[0]
    return "IAT_Resolved__" + dllName



def ProcessFile(filename) :
    f = open(filename, 'r')
    lines = f.readlines()
    f.close()

    ghidraListing = currentProgram.getListing()

    structMembers = []
    currentReferences = []

    for l in lines :
        # Parse the line
        currentInfo = l.split(':')
        currentAddress = currentInfo[0]
        currentLabel = currentInfo[1]

        # There's a reference part on the line
        if len(currentInfo) > 2 :

            Populate(ghidraListing, structMembers, currentReferences)

            # Get ready for the next lines to pick up for the next struct
            structMembers = []

            # Extract the references. E.g.:
            # 0x4000004 : advapi32.&RegDeleteValueW : 0x8002004,0x8002100
            # ==> ['0x8002004', '0x8002100']
            currentReferencesString = currentInfo[2]
            currentReferencesString = currentReferencesString.strip()
            currentReferences = currentReferencesString.split(',')

        # Replace invalid chars
        currentLabel = currentLabel.replace('&', '')
        currentLabel = currentLabel.replace(' ', '')
        currentLabel = currentLabel.replace('.', '_')
        currentLabel = currentLabel.strip()

        structMembers.append( currentLabel )

        ghidraAddress = toAddr(currentAddress)

        print(currentLabel, ghidraAddress)

        createLabel(ghidraAddress, currentLabel, True)

    Populate(ghidraListing, structMembers, currentReferences)

    print("::> Processed " + str(len(lines)) + " lines")



if __name__ == '__main__':
    main()
