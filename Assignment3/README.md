# CPEN442: Introduction to Cybersecurity
## Assignment 3: VPN

In this assignment, you are instructed to implment a Virtual Private Network (VPN) that provides **Confidentiality** and **Integrity** protection through **Mutual Authentication** and **Key Establishment**. This template project gives you a starting point. It is implemented in **Python 3**. 

### Instructions for using this template project:
- Fork this repo to your account, if you want to store your progress on Github.
- Clone this repo (or your own fork) to your local machine.
- Install the requirements of the project using **Python pip** (pip3 install -r requirements.txt).
    - If you encountered `ModuleNotFoundError: No module named 'Tkinter'` on MacOS, `run `brew install python-tk`
- Run the **app.py** file (python3 app.py) to make sure you have all the necessary dependencies to run the program. Install any missing dependencies if the program fails to run.
- Try running two instances of the program and connect them together to make sure the TCP connection works correctly on your setup. Input the **hostname** and **port** numbers on the UI, select the correct mode (**Client** on one side, and **Server** on the other), and click **Create Connection**.
- If the connection is successful, you should see the success message in the **logs** section. You should now be able to send unencrypted messages to the other machine, using the **Send Message** button. Without any modification, the program sends and receives messages un-encrypted, so you are able to test it before implementing encryption.
- To implement your protocol, in both **app.py** and **protocol.py** there are a series of "TODO" comments that points you to where you need to start.
- The user should be able to secure the tunnel by clicking the **Secure Connection** button on the UI. So, once that button is clicked, you should start your protcol (perform mutual authentication and establish the key).
- There is no need for implementing the **Continue** button, if (and only if) you are using this template. If you are not using this template, you need to implement the button. 
- You are allowed to modify any part of **app.py** and **protocol.py**, even outside of the TODO tags. Just make it clear in your report why those changes were necessary.
- If you find a bug in this template, please implement a fix and submit a pull request. You might get bonus points depending on how substantial the bug and fix is. Note that changing the program to fit your protocol does not count as finding a bug.

Good luck.
