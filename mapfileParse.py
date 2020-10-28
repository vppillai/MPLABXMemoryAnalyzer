import re
import os
import shlex
import subprocess
import csv
import re
import inspect
import operator
import pprint
import sys
import time
import argparse

# -------------------------------------------------------------------------------------------
# Globals to store common variables
cleanFileExt = "_clean.map"
buildMode = "production"
projectName = ""
projectPath = ""
outputFolder = ""
mapFilePath = ""
elfFilePath = ""
aMapPath = ""
configName = ""

compDefinition = {
    "Wifi Driver": ["/driver/wifi/"],
    "WiFi Library": ["pic32mzw1.a"],
    "TCP/IP": ["/library/tcpip/"],
    "NetPres": ["/net_pres/"],
    "Memory & FileSystem": ["/driver/memory/","/system/fs/"],
    "Cryptoauthlib": ["/library/cryptoauthlib/"],
    "USB" : ["/usb/","/driver/usb/"],
    "peripherals": ["/peripheral/"],
    "System console, command , Debug": ["/system/command/", "/system/console/", "/system/debug/"],
    "App Debug": ["/system/appdebug/"],
    "Wifi Service": ["/system/wifi/"],
    "Net Service": ["/system/net/"],
    "WiFI Provisioning Service": ["/system/wifiprov/"],
    "MQTT Service": ["/system/mqtt/"],
    "Paho MQTT": ["/third_party/paho.mqtt.embedded-c/"],
    "Free RTOS": ["/src/third_party/rtos/FreeRTOS/"],
    "WolfSSL": ["/third_party/wolfssl/"],
    "stdLib": ["libc.a", "libe.a", "libgcc.a", "libm.a", "libpic32.a"],
}
# -------------------------------------------------------------------------------------------
# generate paths from input project path


def setPaths(inputPath):
    global projectName, projectPath
    projectPath = os.path.realpath(inputPath)
    projectName, extension = os.path.splitext(os.path.basename(projectPath))
    if extension != ".X":
        print("Please provide path until the project name ending in .X")
        exit(-1)

    if not os.path.exists(projectPath):
        print("Project path does not exist")
        exit(-2)

    # This is required since amap is packed into the tool path. But execution might happen from elsewhere.
    global aMapPath
    aMapPath = os.path.join(os.path.dirname(os.path.abspath(
        inspect.getfile(inspect.currentframe()))), "amap.exe")

    global configName
    if not configName:
        configName = projectName

    global outputFolder, buildMode
    outputFolder = os.path.join(
        projectPath, f"dist\\{configName}\\{buildMode}")

    if not os.path.exists(outputFolder):
        print("Output Folder does not exist. Please check configuration Name")
        exit(-2)

    global mapFilePath
    mapFilePath = os.path.join(
        outputFolder, f"{projectName}.X.{buildMode}.map")

    global elfFilePath
    elfFilePath = os.path.join(
        outputFolder, f"{projectName}.X.{buildMode}.elf")

    print("processing: ", elfFilePath)

# -------------------------------------------------------------------------------------------
# check if the compiler tool is availale


def checkTools():
    global elfFilePath
    command = f"xc32-addr2line.exe -v"
    status, result = subprocess.getstatusoutput(
        shlex.split(command, posix=False))
    if status:
        print("  Cant find xc32 tools. Please make sure that the compiler tools path is set in your PATH env")
        exit(-1)

# -------------------------------------------------------------------------------------------
# use the external tool to parse map file into a tab seperated file for further processing


def parseMap(fileName):
    global aMapPath
    command = f"{aMapPath} -f {fileName}"
    # print(shlex.split(command, posix=False))
    subprocess.Popen(shlex.split(command, posix=False)).wait(60)

# -------------------------------------------------------------------------------------------
# delete intermediate files. The cleaned-up map file is retained to use amap GUI for manual analysis


def cleanupOutput(filename, distClean=False):
    global outputFolder, projectName
    csvFileName = os.path.join(outputFolder, projectName+f".X.{buildMode}.csv")
    csvSummaryName = os.path.join(
        outputFolder, projectName+f".X.{buildMode}_summary.csv")
    csvSymsFileName = os.path.join(
        outputFolder, projectName+f".X.{buildMode}_syms.csv")
    csvfileSizeFileName = os.path.join(
        outputFolder, projectName+f".X.{buildMode}_fileSize.csv")
    fileList = [
        f"{filename}.all",
        f"{filename}.module",
        f"{filename}.file",
        f"{filename}.subsection",
        f"{filename}.section",
        csvFileName,
    ]
    if distClean:
        fileList.extend([
            csvSymsFileName,
            csvSummaryName,
            csvfileSizeFileName,
            filename,  # clean map file
        ])
    for file in fileList:
        try:
            os.remove(file)
        except:
            pass

# -------------------------------------------------------------------------------------------
# use GNU tools to map address to file name and line number. The tool can take a bunch of
#   addresses and give corresponding file names in one shot. We are doing it in chunks of
#   2K here since subprocess has a limit on argument length. Had this been done one at a
#   time, it would have taken ever to complete. Some of the addresses cannot be mapped.
#   For these, we do a second pass by readinf DWARF info in getDWfileName().


def addrToFile(file, addrList):

    retFileList = b''

    # break the address list into chunks of 2000
    n = 2000
    addrListChunks = [addrList[i:i + n] for i in range(0, len(addrList), n)]

    for addresses in addrListChunks:
        command = f"xc32-addr2line.exe -e {file} {addresses}"
        process = subprocess.Popen(shlex.split(
            command, posix=False), stdout=subprocess.PIPE)
        retFileList += process.communicate()[0]

    return retFileList

# -------------------------------------------------------------------------------------------
# this is where we use addrToFile() and write in the available file names.


def attachFileNames(filename):
    inputFile = f"{filename}.all"
    elfFileName = filename.replace(cleanFileExt, ".elf")
    csvFileName = filename.replace(cleanFileExt, ".csv")
    addressList = []

    with open(inputFile, newline='') as sections, open(csvFileName, 'w', newline='') as updatedSec:
        section_reader = csv.reader(sections, delimiter='\t')
        writer = csv.writer(updatedSec)
        writer.writerow(["Section", "SubSection", "Address",
                         "Size", "Demangled Name", "Module Name", "File Name", "Mangled Name"])
        # get all addresses int a list
        for section in section_reader:
            addressList.append(section[2])
        sections.seek(0)
        # get the file names
        fileList = addrToFile(elfFileName, addressList)
        for srcFile, section in zip(fileList.decode('utf-8').splitlines(), section_reader):
            if srcFile not in ['??:0', '??:?', '?']:
                # remove line number
                srcFileName = re.match(r'.*(?=:[\d]*|\?$)', srcFile.strip())
                if srcFileName:
                    srcFile = srcFileName.group()
                section[6] = srcFile
            if section[0] not in ['.vectors', '.gnu.attributes']:
                writer.writerow(section)

# -------------------------------------------------------------------------------------------
# look inside the object files under _ext and get original source name from its DWARF info
# at DIE 0. Idea transpired while playing around with https://github.com/vppillai/dwex . But
# not using pyelftools to avoid an external dep.


def getDWfileName(fileName):
    global projectPath
    objPath = os.path.join(projectPath, fileName)
    # Get the level 0 dWARF info from the obj file in _ext
    command = f"xc32-readelf.exe  --debug-dump=info --dwarf-depth=1 {objPath}"
    # parse the output to get DW_AT_name field to get teh matching file name
    AT_NAME_re = re.compile(r'(.*DW_AT_name[ ]*: )(.*)')
    process = subprocess.Popen(shlex.split(
        command, posix=False), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = process.communicate()[0]
    if stdout:
        m = AT_NAME_re.search(stdout.strip().decode('utf-8'))
        if m:
            return((m[2].strip()))

# -------------------------------------------------------------------------------------------
# Finalize filenames to be used for module names. The lib name is used for module name in
#   case of syms coming from pre-compiled libs.


def finalizeFileNames(fileName):
    global projectName
    csvFileName = os.path.splitext(fileName)[0]+".csv"
    moduleFileName = os.path.splitext(fileName)[0]+"_syms.csv"
    # internal store for DW filenames to avoid re-search
    dwFileList = {}

    with open(csvFileName, 'r', newline='') as sections, open(moduleFileName, 'w', newline='') as modules:
        section_reader = csv.reader(sections, delimiter=',')
        module_writer = csv.writer(modules, delimiter=',')
        secLen = len(list(section_reader))
        count = 0
        sections.seek(0)  # rewind file after length read
        for section in section_reader:
            count += 1
            print(f"{count}/{secLen}\r", end="")
            moduleName = section[5]
            fileName = section[6]
            if moduleName:  # there is an existing module name for us to parse
                fileName, extension = os.path.splitext(moduleName)
                if extension in ['.a']:
                    section[5] = os.path.basename(moduleName)
            else:
                # 1. check if we know this file already
                if fileName in dwFileList:
                    section[5] = dwFileList[fileName]
                else:
                    # fetch file name from the obj in _ext
                    objModule = getDWfileName(fileName)
                    if objModule:
                        section[5] = objModule
                        dwFileList[fileName] = objModule
                    else:
                        # if no obj in build, it is coming from some pre-built module
                        section[5] = fileName
            module_writer.writerow(section)


def filewiseSize(fileName):
    moduleFileName = os.path.splitext(fileName)[0]+"_syms.csv"
    sizeFileName = os.path.splitext(fileName)[0]+"_fileSize.csv"
    textPattern = re.compile(r"^\.text\..*$")
    moduleWiseData = {}

    with open(moduleFileName, 'r', newline='') as modules, open(sizeFileName, 'w', newline='') as sizeFile:
        moduleReader = csv.reader(modules, delimiter=",")
        sizeWriter = csv.writer(sizeFile, delimiter=",")
        next(modules)  # skip first line
        for moduleEntry in moduleReader:
            section = moduleEntry[0]
            entrySize = int(moduleEntry[3])
            moduleFile = moduleEntry[5]

            if moduleFile:
                if moduleFile not in moduleWiseData:
                    moduleWiseData[moduleFile] = {
                        "rodata": 0, "data": 0, "bss": 0, "text": 0}
            else:
                if "misc" not in moduleWiseData:  # placeholder for everything else
                    moduleWiseData["misc"] = {
                        "rodata": 0, "data": 0, "bss": 0, "text": 0}
                moduleFile = "misc"

            if section in [".rodata"]:
                moduleWiseData[moduleFile]["rodata"] += entrySize
            elif section in [".data", ".sdata"]:
                moduleWiseData[moduleFile]["data"] += entrySize
            elif section in [".bss", ".sbss"]:
                moduleWiseData[moduleFile]["bss"] += entrySize
            elif (section in [".text"]) or textPattern.match(section):
                moduleWiseData[moduleFile]["text"] += entrySize

        sizeWriter.writerow(["file", "text", "rodata", "data", "bss"])
        for fileEntry, size in moduleWiseData.items():
            sizeWriter.writerow(
                [fileEntry, size["text"], size["rodata"], size["data"], size["bss"]])

        # pprint.pprint(moduleWiseData)


def summarizeComponents(fileName):
    sizeFileName = os.path.splitext(fileName)[0]+"_fileSize.csv"
    summaryFileName = os.path.splitext(fileName)[0]+"_summary.csv"
    componentWiseData = {}

    with open(sizeFileName, 'r', newline='') as sizeFile, open(summaryFileName, 'w', newline='') as summaryFile:
        next(sizeFile)  # skip Header
        sizeReader = csv.reader(sizeFile, delimiter=",")
        summaryWriter = csv.writer(summaryFile, delimiter=",")
        for sizeEntry in sizeReader:
            filePath = sizeEntry[0]
            componentIdentified = False
            for comp, compDefs in compDefinition.items():
                for compDef in compDefs:
                    if compDef in filePath:
                        componentIdentified = True
                        sizeEntry[0] = comp
                        if comp not in componentWiseData:
                            componentWiseData[comp] = {
                                "rodata": 0, "data": 0, "bss": 0, "text": 0}
                        componentWiseData[comp]["text"] += int(sizeEntry[1])
                        componentWiseData[comp]["rodata"] += int(sizeEntry[2])
                        componentWiseData[comp]["data"] += int(sizeEntry[3])
                        componentWiseData[comp]["bss"] += int(sizeEntry[4])
            if not componentIdentified:
                if "others" not in componentWiseData:
                    componentWiseData["others"] = {
                        "rodata": 0, "data": 0, "bss": 0, "text": 0}
                componentWiseData["others"]["text"] += int(sizeEntry[1])
                componentWiseData["others"]["rodata"] += int(sizeEntry[2])
                componentWiseData["others"]["data"] += int(sizeEntry[3])
                componentWiseData["others"]["bss"] += int(sizeEntry[4])

        summaryWriter.writerow(["component", "text", "rodata", "data", "bss"])
        for fileEntry, size in componentWiseData.items():
            summaryWriter.writerow(
                [fileEntry, size["text"], size["rodata"], size["data"], size["bss"]])
        # pprint.pprint(componentWiseData)

# -------------------------------------------------------------------------------------------
# Cleanup the map file by removing debug info comments etc.


def cleanupMapFile(fileName):
    global cleanFileExt
    cleanFileName = os.path.splitext(fileName)[0]+cleanFileExt
    debug_aranges_skipNext = False
    config_skipNext = False
    gnu_attributes_skipNext = False

    with open(fileName, "r") as mapFile, open(cleanFileName, "w") as cleanFile:
        for lineItem in mapFile:

            if (re.search(r"^ \.debug_ranges  .*$", lineItem)):
                continue
            if (re.search(r"^ \.mdebug.abi32  .*$", lineItem)):
                continue
            if (re.search(r"[ ]*^ \.comment       .*$", lineItem)):
                continue
            if (re.search(r"^ \.debug_info    .*$", lineItem)):
                continue
            if (re.search(r"^ \.debug_abbrev  .*$", lineItem)):
                continue
            if (re.search(r"^ \.debug_line  .*$", lineItem)):
                continue
            if (re.search(r"^ \.debug_frame  .*$", lineItem)):
                continue
            if (re.search(r"^ \.debug_str  .*$", lineItem)):
                continue
            if (re.search(r"^ \.debug_loc  .*$", lineItem)):
                continue

            if (re.search(r"^ \.debug_aranges$", lineItem)):  # This item comes in 2 lines
                debug_aranges_skipNext = True
                continue
            if debug_aranges_skipNext:
                debug_aranges_skipNext = False
                continue

#            if (re.search(r"^[ ]*\.gnu.attributes$", lineItem)): #This item comes in 2 lines
#                gnu_attributes_skipNext=True
#                continue
#            if debug_aranges_skipNext:
#                gnu_attributes_skipNext=False
#                continue

            # This item comes in 2 lines
            if (re.search(r"^[ ]*\.config_[A-Z0-9]{8}$", lineItem)):
                config_skipNext = True
                continue
            if config_skipNext:
                config_skipNext = False
                continue
            if (re.search(r"^ \*\(\.config_[A-Z0-9]{8}\)$", lineItem)):
                continue

            # to remove config sections from memory configuration
            if (re.search(r"^config_[A-Z0-9]{8}  0x.*$", lineItem)):
                continue
            if (re.search(r"^configsfrs_[A-Z0-9]{8} 0x.*$", lineItem)):
                continue

            cleanFile.write(lineItem)

# -------------------------------------------------------------------------------------------
# main execution flow


def main(projectPath):
    global cleanFileExt, mapFilePath, outputFolder
    setPaths(projectPath)

    # check if the tools are useable
    checkTools()

    os.chdir(outputFolder)
    cleanFileName = os.path.splitext(mapFilePath)[0]+cleanFileExt

    # delete already geenrated files
    cleanupOutput(cleanFileName, distClean=True)

    # remove debug symbols from the map file
    cleanupMapFile(mapFilePath)

    # parse the file and get component files
    parseMap(cleanFileName)

    # now read the parsed file and translate addresses to line. Some might fail
    print("running addr2Line")
    attachFileNames(cleanFileName)

    # Get file names of remaining from _ext and assign modules in CSV file
    print("parsing DWARF")
    finalizeFileNames(mapFilePath)

    # compute sizeDict per file
    filewiseSize(mapFilePath)

    # Summarize components
    summarizeComponents(mapFilePath)

    # delete the intermediate files
    cleanupOutput(cleanFileName, distClean=False)

    print("See results at :", outputFolder)


# -------------------------------------------------------------------------------------------
# parse input arguments
def parseArguments():
    global configName, projectPath
    parser = argparse.ArgumentParser(
        description="Tool to parse map file and provide component-wise memory usage of an embedded project")
    parser.add_argument("-c", "--config",
                        help="specify a configuration name", metavar="<project config>", type=str)
    parser.add_argument('prjPathArg', nargs=1,
                        metavar="<project path to .X>")
    args = parser.parse_args()
    if (args.config):
        configName = args.config
    if not args.prjPathArg:
        parser.error("please provide a project path to .X")
        exit(-1)
    else:
        projectPath = args.prjPathArg[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parseArguments()

    start = time.time()
    main(projectPath)
    print(f"Process completed in : {time.time() - start}s")
