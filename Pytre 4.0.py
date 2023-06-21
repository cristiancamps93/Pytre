# Cristian Camps Morillo - Getronics - Mitre Coverage Project
"""
#VERSION CONTROL
Version 1.0:
    03/06/2022: First version of the script - provides a json file version 2.2 for attack navigator: https://mitre-attack.github.io/attack-navigator/

Version 2.0:
    25/10/2022: Updated script to match requirements of version 4.6.6 of mitre map. Pytre 2.0

Version 3.0:
    14/11/2022: Updated script to match requirements of version 4.7.1 of Mitre + updated to Mitre 12.
                Added new input file containing the play status + adding different color tags to display in navigator.

Version 4.0:
    20/06/2023: Updating mitre version


# DOCUMENTATION
#https://www.youtube.com/watch?v=8ASjvOIyyl8
#Date codes: https://docs.python.org/3/library/datetime.html#strftime-and-strptime-behavior
"""

# IMPORTS
import pandas as pd
import time
import numpy as np
import json

# Output de alarms por technique y subtechnique TO DO
#Check why there are outputs with 0 in tests correlations

# DISCLAIMER1
print("Hello, please re-fill the excel found in the same folder called 'Input.csv' with the same pattern.")
print("")
print("Notice that the input file must be encoded in UTF-8, otherwise the script won't work :)")
print("")
print("Once executed, this script will provide a json file that needs to be imported into the Mitre web application.")
input("Press any key to execute:")


# MASTER VARIABLES
outputFile = "Output.json"
inputFile = "Input.csv"
minValue = 0 # Set up by Mitre Navigator
maxValue = 100 #Set up by Mitre Navigator
indenter = 4

colorCoverage = "#31a354" #Green
colorNoIntent = "#e60d0d" #Red
colorNotAssessed = "#636363" #Gray
colorPlanned = "#fd8d3c" #Orange
colorNoFeasible = "#931bf5" #Purple

enabled = True
disabled = False

showSubtechniques = disabled #enabled = Show splitted subtechniques in the navigator, disabled = Only show techniques

# END OF MASTER VARIABLES


# Import data from the input as pandas object
def importData(inputF):
    # IMPORT INPUT DATA
    # Technique ID;Play ID;Detection Rule Status
    mitre = pd.read_csv(inputF, sep=';')
    #mitre = mitre.dropna()  # Clean NaN values -> Removed since now all the values must be considered

    return mitre

#Returns a sortered list based on the pandas object from the import function.
def sortPanda(panda):
    panda.sort_values('ID')

    tecnicas = list(panda["ID"])
    plays = list(panda['Play ID'])
    status = list(panda['Detection Rule Status'])

    #Control that the techniques and plays have the same amount of fields
    if (len(tecnicas) - len(plays) == 0) and (len(tecnicas) - len(status) == 0):
        return tecnicas, plays, status
    else:
        print("Import error in techniques or plays, please check that both fields contain the same amount of data")

def writeJason(tecnicas, status):

    # Creating the technique dictionary and filling it with the techniques in a dictionary list

    items = []
    it = 0

    color = ""

    for line in tecnicas:

        if status[it] == "Coverage in place":
            color = colorCoverage
        elif status[it] == "Planned":
            color = colorPlanned
        elif status[it] == "Not assessed":
            color = colorNotAssessed
        elif status[it] == "No intent":
            color = colorNoIntent
        elif status[it] == "Not feasible right now":
            color = colorNoFeasible
        else:
            print("Error in the if condition for the status colors")
            print(status[it])
            break

        dictionaryTechnique = {
            "techniqueID": tecnicas[it],
            "color": color,
            "comment": "",
            "enabled": enabled,
            "metadata": [],
            "links": [],
            "showSubtechniques": showSubtechniques
        }
        items.append(dictionaryTechnique)
        it = it + 1


    #Creating the main dictionary
    dictionary = {
        "name": "Getronics Coverage",
        "versions": {
            "attack": "13",
            "navigator": "4.8.2",
            "layer": "4.4"
        },
        "domain": "enterprise-attack",
        "description": "",
        "filters": {
            "platforms": [
                "Linux",
                "macOS",
                "Windows",
                "Network",
                "PRE",
                "Containers",
                "Office 365",
                "SaaS",
                "Google Workspace",
                "IaaS",
                "Azure AD"
            ]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": items,
        "gradient": {
            "colors": [
                "#ff6666ff",
                "#ffe766ff",
                "#8ec843ff"
            ],
            "minValue": minValue,
            "maxValue": maxValue
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }

    # Serializing json
    json_object = json.dumps(dictionary, indent=indenter)

    # Writing to sample.json
    with open(outputFile, "w") as outfile:
        outfile.write(json_object)


if __name__ == "__main__":
    panda = importData(inputFile)
    tecnicas, plays, status = sortPanda(panda)
    writeJason(tecnicas, status)