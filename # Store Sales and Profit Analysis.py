import tkinter as tk
from tkinter import messagebox
import hashlib
import sqlite3
import matplotlib.pyplot as plt
from datetime import datetime

class StoreDatabase:
    def __init__(self):
        self.conn = sqlite3.connect("store_sales.db")
        self.create_sales_table()

    def create_sales_table(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS sales (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT NOT NULL,
                    sale_amount REAL NOT NULL,
                    cost_amount REAL NOT NULL,
                    profit REAL NOT NULL,
                    date TEXT NOT NULL
                )
            """)

    def add_sale(self, user, sale_amount, cost_amount, profit, date):
        with self.conn:
            self.conn.execute("""
                INSERT INTO sales (user, sale_amount, cost_amount, profit, date)
                VALUES (?, ?, ?, ?, ?)
            """, (user, sale_amount, cost_amount, profit, date))

    def get_sales_by_user(self, user):
        with self.conn:
            return self.conn.execute("SELECT * FROM sales WHERE user = ?", (user,)).fetchall()

    def get_all_sales(self):
        with self.conn:
            return self.conn.execute("SELECT * FROM sales").fetchall()

class UserAuthBackend:
    def __init__(self):
        self.users = {}

    def register(self, username, password):
        if username in self.users:
            return False, "Username already exists"
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = hashed_password
        return True, "Registration successful"

    def login(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if username in self.users and self.users[username] == hashed_password:
            return True, "Login successful"
        return False, "Invalid username or password"

class AdminAuthBackend:
    def __init__(self):
        self.admin_username = "admin"
        self.admin_password = hashlib.sha256("password".encode()).hexdigest()

    def login(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if username == self.admin_username and hashed_password == self.admin_password:
            return True, "Admin login successful"
        return False, "Invalid admin credentials"

class StoreApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Store Management System")
        self.root.attributes('-fullscreen', True)

        self.db = StoreDatabase()
        self.user_auth = UserAuthBackend()
        self.admin_auth = AdminAuthBackend()

        self.current_user = None
        self.create_auth_frame()
        self.create_store_frame()
        self.hide_store_frame()

    def create_auth_frame(self):
        self.auth_frame = tk.Frame(self.root, bg="#f8e473")
        self.auth_frame.pack(fill=tk.BOTH, expand=True)

        self.username_label = tk.Label(self.auth_frame, text="Username:", bg="#f5761a", font=('Helvetica', 20))
        self.username_label.pack(pady=10)
        self.username_entry = tk.Entry(self.auth_frame, font=('Helvetica', 20))
        self.username_entry.pack(pady=10)

        self.password_label = tk.Label(self.auth_frame, text="Password:", bg="#0a1172", fg="white", font=('Helvetica', 20))
        self.password_label.pack(pady=10)
        self.password_entry = tk.Entry(self.auth_frame, show="*", font=('Helvetica', 20))
        self.password_entry.pack(pady=10)

        self.register_btn = tk.Button(self.auth_frame, text="Register", command=self.register_user, bg="#4CAF50", fg="white", font=('Helvetica', 20))
        self.register_btn.pack(pady=10)

        self.login_btn = tk.Button(self.auth_frame, text="Login", command=self.login_user, bg="#2196F3", fg="white", font=('Helvetica', 20))
        self.login_btn.pack(pady=10)

        self.admin_login_btn = tk.Button(self.auth_frame, text="Admin Login", command=self.login_admin, bg="#FF5722", fg="white", font=('Helvetica', 20))
        self.admin_login_btn.pack(pady=10)

    def create_store_frame(self):
        self.store_frame = tk.Frame(self.root, bg="#f8e473")
        self.store_frame.pack(fill=tk.BOTH, expand=True)

        self.name_label = tk.Label(self.store_frame, text="Store Name:", bg="#f25278", font=('Helvetica', 20))
        self.name_label.pack(pady=10)
        self.name_entry = tk.Entry(self.store_frame, font=('Helvetica', 20))
        self.name_entry.pack(pady=10)

        self.sale_label = tk.Label(self.store_frame, text="Sale Amount:", bg="#5cb2c5", font=('Helvetica', 20))
        self.sale_label.pack(pady=10)
        self.sale_entry = tk.Entry(self.store_frame, font=('Helvetica', 20))
        self.sale_entry.pack(pady=10)

        self.cost_label = tk.Label(self.store_frame, text="Cost Amount:", bg="#2c3863", fg="white", font=('Helvetica', 20))
        self.cost_label.pack(pady=10)
        self.cost_entry = tk.Entry(self.store_frame, font=('Helvetica', 20))
        self.cost_entry.pack(pady=10)

        self.add_sale_btn = tk.Button(self.store_frame, text="Add Sale", command=self.add_sale, bg="#2196F3", fg="white", font=('Helvetica', 20))
        self.add_sale_btn.pack(pady=10)

        self.report_btn = tk.Button(self.store_frame, text="Generate Report", command=self.generate_report, bg="#4CAF50", fg="white", font=('Helvetica', 20))
        self.report_btn.pack(pady=10)

        self.logout_btn = tk.Button(self.store_frame, text="Logout", command=self.logout_user, bg="#ff9800", fg="white", font=('Helvetica', 20))
        self.logout_btn.pack(pady=10)

        self.report_text = tk.Text(self.store_frame, height=8, width=40, bg="#f0f0f0", font=('Helvetica', 20))
        self.report_text.pack(pady=10)

    def hide_store_frame(self):
        self.store_frame.pack_forget()

    def show_store_frame(self):
        self.auth_frame.pack_forget()
        self.store_frame.pack(fill=tk.BOTH, expand=True)

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            success, message = self.user_auth.register(username, password)
            messagebox.showinfo("Registration", message)
        else:
            messagebox.showerror("Error", "Please enter both username and password.")

    def login_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            success, message = self.user_auth.login(username, password)
            if success:
                self.current_user = username
                messagebox.showinfo("Login", message)
                self.show_store_frame()
            else:
                messagebox.showerror("Error", message)

    def login_admin(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username == "admin" and password == "password":
            messagebox.showinfo("Admin Login", "Admin login successful!")
            self.admin_dashboard()
        else:
            messagebox.showerror("Error", "Invalid admin credentials.")

    def logout_user(self):
        self.current_user = None
        messagebox.showinfo("Logout", "You have been logged out.")
        self.hide_store_frame()
        self.auth_frame.pack(fill=tk.BOTH, expand=True)

    def admin_dashboard(self):
        sales_data = self.db.get_all_sales()
        if sales_data:
            self.plot_graph(sales_data)
        else:
            messagebox.showerror("Error", "No sales data found.")

    def add_sale(self):
        try:
            sale_amount = float(self.sale_entry.get())
            cost_amount = float(self.cost_entry.get())
            profit = sale_amount - cost_amount
            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.db.add_sale(self.current_user, sale_amount, cost_amount, profit, date)
            messagebox.showinfo("Success", "Sale added successfully!")
        except ValueError:
            messagebox.showerror("Error", "Please enter valid sale and cost amounts.")

    def generate_report(self):
        sales_data = self.db.get_sales_by_user(self.current_user)
        if sales_data:
            self.report_text.delete(1.0, tk.END)
            for row in sales_data:
                self.report_text.insert(tk.END, f"Date: {row[5]}, Sale: {row[2]}, Cost: {row[3]}, Profit: {row[4]}\n")
            self.plot_graph(sales_data)
        else:
            messagebox.showerror("Error", "No sales data found.")

    def plot_graph(self, sales_data):
        dates = [row[5] for row in sales_data]
        profits = [row[4] for row in sales_data]

        plt.figure(figsize=(10, 5))
        plt.plot(dates, profits, marker='o')
        plt.title('Profit Over Time')
        plt.xlabel('Date')
        plt.ylabel('Profit')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = StoreApp(root)
    root.mainloop()
