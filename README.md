# Secure File Sharing Platform

This is a Flask-based web application that provides a secure way to share files. It allows users to register, upload files, and generate shareable links with optional expiration dates and download limits. All uploaded files are encrypted at rest using a file-specific key, which is itself encrypted by a master key.

# Key Features

  User Authentication: Secure user registration and login.

  File Uploads: Users can upload files to the platform.

  End-to-end Encryption: All files are encrypted using a unique key before being saved to the server's disk.

  Secure Sharing Links: Generate unique, shareable links with customizable expiration and download limits.

  File Management: Users can view and delete their uploaded files and associated share links.

  # Create Instance on your preferred webservice provider(I have Used AWS as my Webservice Provider)

  1.Sign In to AWS Management Console 🚀 using - https://aws.amazon.com/console/

  2.Navigate to EC2 Dashboard ☁️ AND In the left-hand navigation pane, under "Instances," click on Instances.

  3.Launch a New Instance ➕

  4.Choose an Amazon Machine Image (AMI) 🐧

   i)Give your instance a descriptive Name

   ii)Select an Amazon Machine Image (AMI) :- I have used Amazon Linux and Make sure to select the correct architecture (usually 64-bit (x86)).

 5.Choose an Instance Type 💻 : I have Used t2.micro

 6.Create or Select a Key Pair (Login) 🔑

   i)Create new key pair. Give it a Key pair name
    
   ii)Click Create key pair. Your private key file (.pem) will be downloaded automatically. Keep this file secure and            private! You will need it to SSH into               your instance.
   
   iii)If you already have a key pair, select it from the dropdown.

7.Configure Network Settings 🌐

  i)Click Edit Network Settings
  
 ii)Security group name: Give it a name
 
iii)Inbound security group rules:

  Rule 1 (SSH): By default, SSH (Port 22) is usually added. Ensure its Source type is set to My IP (for your current IP) or Anywhere (0.0.0.0/0) if you need to connect from       various locations (less secure).

  Rule 2 (Chat App Port): Click Add security group rule.

  Type: Select Custom TCP.

  Port range: Enter 65323.

  Source type: Select Anywhere-IPv4 (0.0.0.0/0). This is crucial for your chat clients to connect from anywhere on the internet.

  Description (optional): Chat App Port

8.Configure Storage 💾 : The default 8 GiB (Gigabytes) of General Purpose SSD (gp2 or gp3) is usually sufficient for a basic server. You can increase it if needed, but stay within the free tier limits if applicable.

9.Review and Launch 🚀 : Review all your settings before launching And Click Launch instance.

   After Launching the Instance , Check the status as Running and then check for your Public IP address.

# Upload your app.py and all the .html files present in templates folder

From your local Kali Linux terminal :scp -i /path/to/your/key-pair-name.pem /path/to/local/app.py ec2-user@YOUR_PUBLIC_IP_ADDRESS:/home/ec2-user

  Replace /path/to/your/key-pair-name.pem with the actual path and filename of your .pem
  
  Replace /path/to/local/app.py with actual path and filename of your app.py file and .html files

# Connect EC2 instance using .pem file

1.Locate Your .pem File 📂

2.Set Correct Permissions using command : chmod 400 /path/to/your/key-pair-name.pem

  Replace /path/to/your/key-pair-name.pem with the actual path and filename of your .pem

3.Connect to Your EC2 Instance via SSH 🚀 using command : ssh -i /path/to/your/key-pair-name.pem ec2-user@YOUR_PUBLIC_IP_ADDRESS

  Replace /path/to/your/key-pair-name.pem with the actual path and filename of your .pem

## Run app.py using the command : python3 app.py

## Web Access
  
  1.Open Browser

  2.search for YOUR_PUBLIC_IP_ADDRESS:65323

# ENJOY SAFE AND SECURE FILE SHARING!!

