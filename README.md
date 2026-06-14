A lightweight SMTP enumeration tool for identifying valid users on a target mail server. Supports banner grabbing and user verification via the VRFY and EXPN commands. Traffic is encrypted using AES-ECB with a user-supplied or auto-generated key.

Usage
# Banner grab
python smtp_enum.py -i 192.168.0.1

# User enumeration
python smtp_enum.py -i 192.168.0.1 -u root -c VRFY -k <hex_key>
Options
-i   Target IP
-u   Username to verify
-c   Command to use (VRFY or EXPN)
-k   Hex-encoded AES encryption key (required for user enumeration)
