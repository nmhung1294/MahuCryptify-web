#sub string
def pre_solve(string):
    """
    Preprocesses the string before solving
    """
    string = string.upper()
    string = "".join([char for char in string if char.isalpha() or char.isdigit()])
    return string

def sub_string(string, len_each):
    """
    Returns a list of substrings of the given length
    """
    return [string[i:i + len_each] for i in range(0, len(string), len_each)]

def convert_str_to_int(string):
    """
    Converts a string to integer in base 10
    """
    res = 0
    i = len(string) - 1
    for char in string:
        res += (ord(char) - 65) * 26 ** i
        i -= 1
    return res

def convert_int_to_str(number):
    """
    Converts an integer in base 26 to a string
    """
    res = ""
    while number > 0:
        res = chr(number % 26 + 65) + res
        number = number // 26
    return res

