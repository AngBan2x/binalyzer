# common/helpers.py: helper functions that will be used all around the project

def rprint_dict(x=dict, level=0):
    """
    Recursively prints a nested dictionary in indented hierarchical order
    
    Args:
        x(dict): Given dictionary. Must be provided
        level(int): Level of hierarchy of the provided dictionary. Level 0 indicates the root dictionary, Levels >1 indicate a dictionary inside the root/parent dictionary
    """

    for key, value in x.items():
        if str(type(value)) == "<class \'dict\'>": # if the value is another dictionary
            print(f"{'\t' * level}{key} :")
            rprint_dict(value, level+1)
            print(" ")
        elif str(type(value)) == "<class \'list\'>": # if the value is a list
            print(f"{'\t' * level}{key} :")
            for i in range(len(value)):
                print(f"{'\t' * (level + 1)}[{i}]")
                rprint_dict(value[i], level+1)
                print(" ")
        else:
            print(f"{'\t' * level}{key} : {value}")