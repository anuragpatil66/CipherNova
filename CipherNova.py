# Done by Anurag Patil - https://www.linkedin.com/in/anurag-patil-2a9b0022a/

import os  # Importing the 'os' module allows for interaction with the operating system.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Importing 'PBKDF2HMAC' from 'cryptography.hazmat.primitives.kdf.pbkdf2' module for key derivation.
from cryptography.hazmat.primitives import hashes  # Importing 'hashes' from 'cryptography.hazmat.primitives' module for cryptographic hashing.
from cryptography.hazmat.primitives import padding  # Importing 'padding' from 'cryptography.hazmat.primitives' module for data padding.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Importing 'Cipher', 'algorithms', and 'modes' from 'cryptography.hazmat.primitives.ciphers' module for symmetric encryption.

"""
generate_key_from_password_aes(password, salt):

a)This function generates a key for AES encryption from a given password and salt.
b)It uses the PBKDF2HMAC key derivation function with SHA-256 as the cryptographic hash algorithm.
c)The derived key length is set to 32 bytes.
d)The function encodes the password as UTF-8 and derives the key using the key derivation function.
e)The generated key is returned.
"""
def generate_key_from_password_aes(password, salt):
    # Function to generate a key for AES encryption from a given password and salt.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Using the SHA-256 cryptographic hash algorithm.
        length=32,  # Setting the length of the derived key to 32 bytes.
        salt=salt,  # Setting the salt value.
        iterations=100000,  # Setting the number of iterations for the key derivation algorithm.
    )
    key = kdf.derive(password.encode('utf-8'))  # Deriving the key from the password by encoding it as UTF-8 and using the key derivation function (KDF).
    return key

"""
generate_key_from_password_camellia(password, salt):

a)This function generates a key for Camellia encryption from a given password and salt.
b)It uses the PBKDF2HMAC key derivation function with SHA-256 as the cryptographic hash algorithm.
c)The derived key length is set to 32 bytes.
d)The function encodes the password as UTF-8 and derives the key using the key derivation function.
e)The generated key is returned.
"""
def generate_key_from_password_camellia(password, salt):
    # Function to generate a key for Camellia encryption from a given password and salt.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Using the SHA-256 cryptographic hash algorithm.
        length=32,  # Setting the length of the derived key to 32 bytes.
        salt=salt,  # Setting the salt value.
        iterations=100000,  # Setting the number of iterations for the key derivation algorithm.
    )
    key = kdf.derive(password.encode('utf-8'))  # Deriving the key from the password by encoding it as UTF-8 and using the key derivation function (KDF).
    return key

"""
encrypt_file_aes(file_path, password):

a)This function encrypts a file using AES encryption.
b)It reads the contents of the file specified by file_path.
c)Generates a random salt and an initialization vector (IV) of 16 bytes each.
d)Calls generate_key_from_password_aes to generate the encryption key from the password and salt.
e)Creates an AES cipher object with the key and IV in CBC mode.
f)Creates an encryptor object using the AES cipher.
g)Creates a padder object for PKCS7 padding with a block size of 128 bits.
h)Encrypts the data by applying padding, encrypting, and finalizing.
i)Creates an encrypted file path by appending '.enc' to the original file's base name.
j)Writes the salt, IV, and encrypted data to the encrypted file.
k)Prints a success message indicating the file has been encrypted and saved.
"""
def encrypt_file_aes(file_path, password):
    # Function to encrypt a file using AES encryption.
    with open(file_path, 'rb') as file:
        data = file.read()  # Reading the contents of the file into the 'data' variable.

    salt = os.urandom(16)  # Generating a random salt of 16 bytes.
    key = generate_key_from_password_aes(password, salt)  # Generating the encryption key from the password and salt.
    iv = os.urandom(16)  # Generating a random initialization vector (IV) of 16 bytes.

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # Creating an AES cipher object with the generated key and IV in CBC mode.
    encryptor = cipher.encryptor()  # Creating an encryptor object using the AES cipher.
    padder = padding.PKCS7(128).padder()  # Creating a padder object for PKCS7 padding with a block size of 128 bits.

    encrypted_data = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()  # Encrypting the data by applying padding, encrypting, and finalizing.

    file_name, file_ext = os.path.splitext(file_path)  # Splitting the file path into the base name and extension.
    file_path_encrypted = file_name + file_ext + '.enc'  # Appending '.enc' to the base name to create the encrypted file path.

    with open(file_path_encrypted, 'wb') as file:
        # Writing the salt, IV, and encrypted data to the encrypted file.
        file.write(salt)
        file.write(iv)
        file.write(encrypted_data)

    print()
    print("File encrypted and saved successfully to " + file_path_encrypted)  # Printing a success message indicating the file has been encrypted and saved.

"""
encrypt_file_camellia(file_path, password):

a)This function encrypts a file using Camellia encryption.
b)It reads the contents of the file specified by file_path.
c)Generates a random salt and an initialization vector (IV) of 16 bytes each.
d)Calls generate_key_from_password_camellia to generate the encryption key from the password and salt.
e)Creates a Camellia cipher object with the key and IV in CBC mode.
f)Creates an encryptor object using the Camellia cipher.
g)Creates a padder object for PKCS7 padding with a block size of 128 bits.
h)Encrypts the data by applying padding, encrypting, and finalizing.
i)Creates an encrypted file path by appending '.enc' to the original file's base name.
j)Writes the salt, IV, and encrypted data to the encrypted file.
k)Prints a success message indicating the file has been encrypted and saved.
"""
def encrypt_file_camellia(file_path, password):
    # Function to encrypt a file using Camellia encryption.
    with open(file_path, 'rb') as file:
        data = file.read()  # Reading the contents of the file into the 'data' variable.

    salt = os.urandom(16)  # Generating a random salt of 16 bytes.
    key = generate_key_from_password_camellia(password, salt)  # Generating the encryption key from the password and salt.
    iv = os.urandom(16)  # Generating a random initialization vector (IV) of 16 bytes.

    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))  # Creating a Camellia cipher object with the generated key and IV in CBC mode.
    encryptor = cipher.encryptor()  # Creating an encryptor object using the Camellia cipher.
    padder = padding.PKCS7(128).padder()  # Creating a padder object for PKCS7 padding with a block size of 128 bits.

    encrypted_data = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()  # Encrypting the data by applying padding, encrypting, and finalizing.

    file_name, file_ext = os.path.splitext(file_path)  # Splitting the file path into the base name and extension.
    file_path_encrypted = file_name + file_ext + '.enc'  # Appending '.enc' to the base name to create the encrypted file path.

    with open(file_path_encrypted, 'wb') as file:
        # Writing the salt, IV, and encrypted data to the encrypted file.
        file.write(salt)
        file.write(iv)
        file.write(encrypted_data)

    print()
    print("File encrypted and saved successfully. " + file_path_encrypted)  # Printing a success message indicating the file has been encrypted and saved.

"""
encrypt_new_file_aes(password):

a)This function encrypts new data entered by the user using AES encryption.
b)Prompts the user to enter text data.
c)Prompts the user to enter a file path to save the encrypted data, restricting the file extension to '.txt'.
d)Generates a random salt and an initialization vector (IV) of 16 bytes each.
e)Calls generate_key_from_password_aes to generate the encryption key from the password and salt.
f)Creates an AES cipher object with the key and IV in CBC mode.
g)Creates an encryptor object using the AES cipher.
h)Creates a padder object for PKCS7 padding with a block size of 128 bits.
j)Encrypts the data by applying padding, encrypting, and finalizing.
k)Writes the salt, IV, and encrypted data to the specified file path.
l)Prints a success message indicating the data has been encrypted and saved.
"""
def encrypt_new_file_aes(password):
    print()
    data = input("Enter the data (text) to encrypt: ").encode('utf-8')  # Prompting the user to enter text data to encrypt.

    while True:
        print()
        file_path = input("Enter the file path to save encrypted data (TXT extension only) (in this format only X:\\Path\\Path\\anything.txt): ")
        directory, filename = os.path.split(file_path)  # Splitting the file path into the directory and filename.
        file_name, file_ext = os.path.splitext(filename)  # Splitting the filename into the base name and extension.

        if not os.path.exists(directory):  # Checking if the specified directory path exists.
            print()
            print("Invalid directory path. The specified directory does not exist.")
            continue

        if file_ext.lower() != '.txt':  # Checking if the file extension is '.txt'.
            print()
            print("Invalid file extension. Please enter a file path with the .txt extension.")
            continue
        break

    new_file_path = os.path.join(directory, file_name + file_ext + ".enc")  # Creating the path for the new encrypted file.

    salt = os.urandom(16)  # Generating a random salt of 16 bytes.
    key = generate_key_from_password_aes(password, salt)  # Generating the encryption key from the password and salt.
    iv = os.urandom(16)  # Generating a random initialization vector (IV) of 16 bytes.

    with open(new_file_path, 'wb') as file:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # Creating an AES cipher object with the generated key and IV in CBC mode.
        encryptor = cipher.encryptor()  # Creating an encryptor object using the AES cipher.
        padder = padding.PKCS7(128).padder()  # Creating a padder object for PKCS7 padding with a block size of 128 bits.
        encrypted_data = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()  # Encrypting the data by applying padding, encrypting, and finalizing.
        file.write(salt)
        file.write(iv)
        file.write(encrypted_data)

    print()
    print("Data encrypted and saved successfully to " + new_file_path)  # Printing a success message indicating the data has been encrypted and saved.

"""
encrypt_new_file_camellia(password):

a)This function encrypts new data entered by the user using Camellia encryption.
b)Prompts the user to enter text data.
c)Prompts the user to enter a file path to save the encrypted data, restricting the file extension to '.txt'.
d)Generates a random salt and an initialization vector (IV) of 16 bytes each.
e)Calls generate_key_from_password_camellia to generate the encryption key from the password and salt.
f)Creates a Camellia cipher object with the key and IV in CBC mode.
g)Creates an encryptor object using the Camellia cipher.
h)Creates a padder object for PKCS7 padding with a block size of 128 bits.
i)Encrypts the data by applying padding, encrypting, and finalizing.
j)Writes the salt, IV, and encrypted data to the specified file path.
k)Prints a success message indicating the data has been encrypted and saved.
"""
def encrypt_new_file_camellia(password):
    print()
    data = input("Enter the data (text) to encrypt: ").encode('utf-8')  # Prompting the user to enter text data to encrypt.

    while True:
        print()
        file_path = input("Enter the file path to save encrypted data (TXT extension only) (in this format only X:\\Path\\Path\\anything.txt): ")
        directory, filename = os.path.split(file_path)  # Splitting the file path into the directory and filename.
        file_name, file_ext = os.path.splitext(filename)  # Splitting the filename into the base name and extension.

        if not os.path.exists(directory):  # Checking if the specified directory path exists.
            print()
            print("Invalid directory path. The specified directory does not exist.")
            continue

        if "]" in file_path:  # Checking if the file path contains the ']' character.
            print()
            print("Invalid file path. Please enter a valid file path.")
            continue

        if file_ext.lower() != '.txt':  # Checking if the file extension is '.txt'.
            print()
            print("Invalid file extension. Please enter a file path with the .txt extension.")
            continue
        break

    new_file_path = os.path.join(directory, file_name + file_ext + ".enc")  # Creating the path for the new encrypted file.

    salt = os.urandom(16)  # Generating a random salt of 16 bytes.
    key = generate_key_from_password_camellia(password, salt)  # Generating the encryption key from the password and salt.
    iv = os.urandom(16)  # Generating a random initialization vector (IV) of 16 bytes.

    with open(new_file_path, 'wb') as file:
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))  # Creating a Camellia cipher object with the generated key and IV in CBC mode.
        encryptor = cipher.encryptor()  # Creating an encryptor object using the Camellia cipher.
        padder = padding.PKCS7(128).padder()  # Creating a padder object for PKCS7 padding with a block size of 128 bits.
        encrypted_data = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()  # Encrypting the data by applying padding, encrypting, and finalizing.
        file.write(salt)
        file.write(iv)
        file.write(encrypted_data)

    print()
    print("Data encrypted and saved successfully to " + new_file_path)  # Printing a success message indicating the data has been encrypted and saved.

"""
decrypt_existing_file_aes(file_path, password):

a)Checks if the provided file path is a valid file and if it has the .enc extension indicating an encrypted file.
b)If the file path is not valid or doesn't have the correct extension, it prints an error message and returns.
c)Checks if the file specified by the file path exists.
d)If the file doesn't exist, it extracts the file name from the file path and prints an error message indicating that the file doesn't exist.
e)If the file exists, it calls the decrypt_file_aes function to decrypt the file using AES encryption and the provided password.
"""
def decrypt_existing_file_aes(file_path, password):
    # Function to decrypt an existing file that has been encrypted using AES encryption.
    if not os.path.isfile(file_path) or not file_path.endswith('.enc'):
        # Checking if the file path is valid and if it has the '.enc' extension indicating an encrypted file.
        print()
        print("Invalid file format. Only encrypted files can be decrypted.")
        return

    if not os.path.exists(file_path):
        # Checking if the file specified by the file path exists.
        file_name = os.path.basename(file_path)  # Extracting the filename from the file path.
        print()
        print(f"{file_name} doesn't exist in the provided location.")
        return

    decrypt_file_aes(file_path, password)

"""
decrypt_existing_file_camellia(file_path, password):

a)Checks if the provided file path is a valid file and if it has the .enc extension indicating an encrypted file.
b)If the file path is not valid or doesn't have the correct extension, it prints an error message and returns.
c)Checks if the file specified by the file path exists.
d)If the file doesn't exist, it extracts the file name from the file path and prints an error message indicating that the file doesn't exist.
e)If the file exists, it calls the decrypt_file_camellia function to decrypt the file using Camellia encryption and the provided password.
"""
def decrypt_existing_file_camellia(file_path, password):
    # Function to decrypt an existing file that has been encrypted using Camellia encryption.
    if not os.path.isfile(file_path) or not file_path.endswith('.enc'):
        # Checking if the file path is valid and if it has the '.enc' extension indicating an encrypted file.
        print()
        print("Invalid file format. Only encrypted files can be decrypted.")
        return

    if not os.path.exists(file_path):
        # Checking if the file specified by the file path exists.
        file_name = os.path.basename(file_path)  # Extracting the filename from the file path.
        print()
        print(f"{file_name} doesn't exist in the provided location.")
        return

    decrypt_file_camellia(file_path, password)

"""
decrypt_file_aes(filename, password):

a)Opens the file specified by the filename in binary mode.
b)Reads the first 16 bytes (salt), next 16 bytes (IV), and the remaining contents of the file (encrypted data).
c)Enters a loop to handle potential decryption failures due to incorrect passwords.
d)Tries to derive the encryption key using the provided password and salt.
e)Creates an AES cipher object with the derived key and IV in CBC mode.
f)Creates a decryptor object using the AES cipher.
g)Creates an unpadder object for PKCS7 padding with a block size of 128 bits.
h)Decrypts the data by applying padding, decrypting, and finalizing.
i)Removes the .enc extension from the original file name to get the decrypted file name.
j)Opens a new file with the decrypted file name in binary mode and writes the decrypted data.
k)Prints a success message indicating that the file has been decrypted and saved.
l)If a ValueError occurs (indicating an incorrect password), it prints an error message and prompts the user to enter the correct password.
"""
def decrypt_file_aes(filename, password):
    # Function to decrypt a file that has been encrypted using AES encryption.
    with open(filename, 'rb') as file:
        salt = file.read(16)  # Reading the first 16 bytes (salt) from the file.
        iv = file.read(16)  # Reading the next 16 bytes (IV) from the file.
        encrypted_data = file.read()  # Reading the remaining contents of the file (encrypted data).
        
    while True:
        try:
            key = generate_key_from_password_aes(password, salt)  # Deriving the encryption key using the provided password and salt.
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # Creating an AES cipher object with the derived key and IV in CBC mode.
            decryptor = cipher.decryptor()  # Creating a decryptor object using the AES cipher.
            unpadder = padding.PKCS7(128).unpadder()  # Creating an unpadder object for PKCS7 padding with a block size of 128 bits.
            decrypted_data = unpadder.update(decryptor.update(encrypted_data) + decryptor.finalize()) + unpadder.finalize()  # Decrypting the data by applying padding, decrypting, and finalizing.

            decrypted_filename = filename[:-4]  # Removing the '.enc' extension from the original file name.
            with open(decrypted_filename, 'wb') as file:
                file.write(decrypted_data)  # Writing the decrypted data to a new file with the original file name.

            print()
            print("File decrypted and saved successfully to " + decrypted_filename)  # Printing a success message indicating the file has been decrypted and saved.
            break
        except ValueError:
            print()
            print("Invalid password, try again.")
            print()
            password = input("Enter the password to be used for encryption: ")  # Prompting the user to enter the correct password.

"""
decrypt_file_camellia function(filename, password):

a)Opens the file specified by the filename in binary mode.
b)Reads the first 16 bytes (salt), next 16 bytes (IV), and the remaining contents of the file (encrypted data).
c)Enters a loop to handle potential decryption failures due to incorrect passwords.
d)Tries to derive the encryption key using the provided password and salt.
e)Creates a Camellia cipher object with the derived key and IV in CBC mode.
f)Creates a decryptor object using the Camellia cipher.
g)Creates an unpadder object for PKCS7 padding with a block size of 128 bits.
h)Decrypts the data by applying padding, decrypting, and finalizing.
i)Removes the .enc extension from the original file name to get the decrypted file name.
j)Opens a new file with the decrypted file name in binary mode and writes the decrypted data.
k)Prints a success message indicating that the file has been decrypted and saved.
l)If a ValueError occurs (indicating an incorrect password), it prints an error message and prompts the user to enter the correct password.
"""
def decrypt_file_camellia(filename, password):
    # Function to decrypt a file that has been encrypted using Camellia encryption.
    with open(filename, 'rb') as file:
        salt = file.read(16)  # Reading the first 16 bytes (salt) from the file.
        iv = file.read(16)  # Reading the next 16 bytes (IV) from the file.
        encrypted_data = file.read()  # Reading the remaining contents of the file (encrypted data).

    while True:
        try:
            key = generate_key_from_password_camellia(password, salt)  # Deriving the encryption key using the provided password and salt.
            cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))  # Creating a Camellia cipher object with the derived key and IV in CBC mode.
            decryptor = cipher.decryptor()  # Creating a decryptor object using the Camellia cipher.
            unpadder = padding.PKCS7(128).unpadder()  # Creating an unpadder object for PKCS7 padding with a block size of 128 bits.
            decrypted_data = unpadder.update(decryptor.update(encrypted_data) + decryptor.finalize()) + unpadder.finalize()  # Decrypting the data by applying padding, decrypting, and finalizing.

            decrypted_filename = filename[:-4]  # Removing the '.enc' extension from the original file name.
            with open(decrypted_filename, 'wb') as file:
                file.write(decrypted_data)  # Writing the decrypted data to a new file with the original file name.

            print()
            print("File decrypted and saved successfully to " + decrypted_filename)  # Printing a success message indicating the file has been decrypted and saved.
            break
        except ValueError:
            print()
            print("Invalid password, try again.")
            print()
            password = input("Enter the password to be used for encryption: ")  # Prompting the user to enter the correct password.

"""
encrypt_existing_file_aes(file_path, password):

a)Checks if the provided file path is a valid file.
b)If the file path is not valid, it prints an error message and returns.
c)Calls the encrypt_file_aes function to encrypt the file using AES encryption and the provided password.
"""
def encrypt_existing_file_aes(file_path, password):
    # Function to encrypt an existing file using AES encryption.
    if not os.path.isfile(file_path):
        # Checking if the file path is valid and corresponds to an existing file.
        print()
        print("Invalid file format. Please provide a valid file path.")
        return

    encrypt_file_aes(file_path, password)  # Calling the 'encrypt_file_aes' function to encrypt the file.

"""
encrypt_existing_file_camellia(file_path, password):

a)Checks if the provided file path is a valid file.
b)If the file path is not valid, it prints an error message and returns.
c)Opens the file specified by the file path in binary mode and reads its contents into the data variable.
d)Generates a random 16-byte salt.
e)Generates the encryption key from the password and salt using the generate_key_from_password_camellia function.
f)Generates a random 16-byte initialization vector (IV).
g)Creates a Camellia cipher object with the generated key and IV in CBC (Cipher Block Chaining) mode.
h)Creates an encryptor object using the Camellia cipher.
i)Creates a padder object for PKCS7 padding with a block size of 128 bits.
j)Encrypts the data by applying padding, encrypting, and finalizing.
k)Splits the file path into the file name and extension.
l)Creates the encrypted file path by appending the '.enc' extension to the original file name.
m)Opens the encrypted file in binary mode and writes the salt, IV, and encrypted data.
n)Prints a success message indicating that the file has been encrypted and saved.
"""
def encrypt_existing_file_camellia(file_path, password):
    # Function to encrypt an existing file using Camellia encryption.
    if not os.path.isfile(file_path):
        # Checking if the file path is a valid file.
        print()
        print("Invalid file format. Please provide a valid file path.")
        return

    with open(file_path, 'rb') as file:
        # Opening the file specified by the file path in binary mode and reading its contents.
        data = file.read()

    salt = os.urandom(16)  # Generating a random salt of 16 bytes.
    key = generate_key_from_password_camellia(password, salt)  # Generating the encryption key from the password and salt.
    iv = os.urandom(16)  # Generating a random initialization vector (IV) of 16 bytes.

    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))  # Creating a Camellia cipher object with the generated key and IV in CBC mode.
    encryptor = cipher.encryptor()  # Creating an encryptor object using the Camellia cipher.
    padder = padding.PKCS7(128).padder()  # Creating a padder object for PKCS7 padding with a block size of 128 bits.
    encrypted_data = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()  # Encrypting the data by applying padding, encrypting, and finalizing.

    file_name, file_ext = os.path.splitext(file_path)  # Splitting the file path into the file name and extension.
    file_path_encrypted = file_name + file_ext + '.enc'  # Creating the encrypted file path by appending '.enc' to the original file name.

    with open(file_path_encrypted, 'wb') as file:
        # Opening the encrypted file in binary mode.
        file.write(salt)  # Writing the salt to the file.
        file.write(iv)  # Writing the IV to the file.
        file.write(encrypted_data)  # Writing the encrypted data to the file.

    print()
    print("File encrypted and saved successfully to " + file_path_encrypted)  # Printing a success message indicating that the file has been encrypted and saved.

"""
validate_file_path(file_path, encrypted=False):

a)Validates the provided file path.
b)Extracts the directory from the file path.
c)Splits the file path into the file name and extension.
d)If the file is expected to be encrypted (encrypted=True) and the extension is not '.enc', it prints an error message and returns False.
e)If the specified directory doesn't exist, it prints an error message and returns False.
f)If the file path doesn't correspond to a valid file, it prints an error message and returns False.
g)If all the validation checks pass, it returns True to indicate that the file path is valid.
"""
def validate_file_path(file_path, encrypted=False):
    # Function to validate the file path.
    directory = os.path.dirname(file_path)  # Extracting the directory from the file path.

    file_name, file_ext = os.path.splitext(file_path)  # Splitting the file path into the file name and extension.

    if encrypted and file_ext.lower() != '.enc':
        # Checking if the file is expected to be encrypted and if the extension is not '.enc'.
        print()
        print("Invalid file extension. Please enter a file path with the .enc extension.")
        return False

    if not os.path.exists(directory):
        # Checking if the specified directory path exists.
        print()
        print("Invalid directory path. The specified directory does not exist.")
        return False

    if not os.path.isfile(file_path):
        # Checking if the file path corresponds to a valid file.
        print()
        print("Invalid file path. Please enter a valid file path.")
        return False

    return True  # Returning True if the file path passes all the validation checks.

"""
The code defines a main function that serves as the entry point of the program. It presents a menu-driven interface for performing various encryption operations using different encryption algorithms.

a)The program prints a welcome message.
b)Enters an infinite loop to keep displaying the menu options until the user chooses to exit.
c)The user is prompted to select an encryption algorithm (AES or Camellia) or exit the program.
d)If the user selects AES encryption (choice '1'), another loop is entered to present AES-specific encryption options.
e)The user can choose to encrypt an existing file, decrypt an existing file, encrypt new data, return to the main menu, or exit the program.
f)Depending on the chosen option, the program interacts with the user to collect necessary information such as file paths, passwords, etc.
g)The corresponding encryption or decryption functions are called based on the user's choices, along with the provided parameters.
h)Similar steps are followed for Camellia encryption (choice '2').
i)If the user chooses to exit (choice '3'), the program exits gracefully.
j)If an invalid encryption algorithm choice is made, an appropriate error message is displayed.
k)The main function is called when the script is run, initiating the execution of the program.
"""
def main():
    # Main function that acts as the entry point of the program.
    print("\n","Welcome to CipherNova - A comprehensive file encryption tool using AES and Camellia algorithms with CBC mode for secure data protection")
    print("------------------------------------------------------------------------------------------------------------------------------------------")

    while True:
        print("Select the encryption algorithm:")
        print("1) AES with CBC Encryption")
        print("2) Camellia with CBC Encryption")
        print("3) Exit")
        encryption_choice = input("Enter your choice (1/2/3): ")

        if encryption_choice == '1':
            while True:
                print()
                print("1. Encrypt an existing file using AES with CBC Encryption")
                print("2. Decrypt an existing file using AES with CBC Encryption")
                print("3. Encrypt new data using AES with CBC Encryption")
                print("4. Exit to Main Menu")
                print("5. Exit")
                print()
                choice = input("Enter your choice (1/2/3/4/5): ")

                if choice == '1':
                    while True:
                        print()
                        file_path = input("Enter the file path to encrypt (in this format only X:\\Path\\Path\\anything.xxx): ")
                        if validate_file_path(file_path):
                            break
                    print()
                    password = input("Enter the password to be used for encryption: ")
                    encrypt_existing_file_aes(file_path, password)
                elif choice == '2':
                    while True:
                        print()
                        file_path = input("Enter the file path to decrypt (in this format only X:\\Path\\Path\\anything.xxx): ")
                        if validate_file_path(file_path, encrypted=True):
                            break
                    print()
                    password = input("Enter the password to be used for encryption: ")
                    decrypt_existing_file_aes(file_path, password)
                elif choice == '3':
                    print()
                    password = input("Enter the password to be used for encryption: ")
                    encrypt_new_file_aes(password)
                elif choice == '4':
                    break
                elif choice == '5':
                    print()
                    print("Thank You For Using CipherNova")
                    return
                else:
                    print()
                    print("Invalid choice.")

        elif encryption_choice == '2':
            while True:
                print()
                print("1. Encrypt an existing file using Camellia with CBC Encryption")
                print("2. Decrypt an existing file using Camellia with CBC Encryption")
                print("3. Encrypt new data using Camellia with CBC Encryption")
                print("4. Exit to Main Menu")
                print("5. Exit")
                print()
                choice = input("Enter your choice (1/2/3/4/5): ")

                if choice == '1':
                    while True:
                        print()
                        file_path = input("Enter the file path to encrypt (in this format only X:\\Path\\Path\\anything.xxx): ")
                        if validate_file_path(file_path):
                            break
                    print()
                    password = input("Enter the password to be used for encryption: ")
                    encrypt_existing_file_camellia(file_path, password)
                elif choice == '2':
                    while True:
                        print()
                        file_path = input("Enter the file path to decrypt (in this format only X:\\Path\\Path\\anything.xxx): ")
                        if validate_file_path(file_path, encrypted=True):
                            break
                    print()
                    password = input("Enter the password to be used for encryption: ")
                    decrypt_existing_file_camellia(file_path, password)
                elif choice == '3':
                    print()
                    password = input("Enter the password to be used for encryption: ")
                    encrypt_new_file_camellia(password)
                elif choice == '4':
                    break
                elif choice == '5':
                    print()
                    print("Thank You For Using CipherNova")
                    return
                else:
                    print()
                    print("Invalid choice.")

        elif encryption_choice == '3':
            print()
            print("Thank You For Using CipherNova")
            return

        else:
            print()
            print("Invalid encryption algorithm choice.")

"""
The code checks if the script is being run directly (as the main module) or if it is being imported by another module.

a)If the script is being run directly, the condition __name__ == '__main__' evaluates to True, and the code proceeds to call the main function.
b)If the script is being imported by another module, the condition __name__ == '__main__' evaluates to False, and the main function is not executed. This prevents the script's code from running if it is imported as a module, allowing it to be used as a library or component in another program.
"""
if __name__ == '__main__':
    main()
