import tkinter as tk
from threading import Thread
from tkinter import messagebox

from Alice import Alice


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Client")
        self.root.geometry("300x200")

        self.alice = Alice()

        self.username_label = tk.Label(self.root, text="Username:")
        self.username_label.pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        self.password_label = tk.Label(self.root, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(self.root, text="Login", command=self.login)
        self.login_button.pack()

        self.transaction_label = tk.Label(self.root, text="Transaction:")
        self.transaction_label.pack()
        self.transaction_entry = tk.Entry(self.root)
        self.transaction_entry.pack()

        self.amount_label = tk.Label(self.root, text="Amount:")
        self.amount_label.pack()
        self.amount_entry = tk.Entry(self.root)
        self.amount_entry.pack()

        self.transaction_button = tk.Button(self.root, text="Perform Transaction", command=self.perform_transaction)
        self.transaction_button.pack()

        self.result_label = tk.Label(self.root, text="")
        self.result_label.pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:  # Check if username and password are not empty
            # Create a thread to handle authentication
            self.authenticate(username,password)
        else:
            messagebox.showerror("Error", "Please enter both username and password.")

    def authenticate(self, username, password):
        if self.alice.verify_authentication(username, password):
            self.root.after(0, lambda: messagebox.showinfo("Authentication", "User authenticated successfully."))
            self.alice.key_distribution()
        else:
            self.root.after(0, lambda: messagebox.showerror("Authentication",
                                                            "Authentication failed. Invalid username and/or password."))

    def perform_transaction(self):
        action = self.transaction_entry.get()
        amount = self.amount_entry.get()
        self.alice.perform_transaction(action, amount)
        self.result_label.config(text="Transaction completed.")


def main():
    root = tk.Tk()
    client_gui = ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
