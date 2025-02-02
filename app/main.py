import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, date
from flask_login import current_user
from numpy import extract
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, abort, render_template, request, redirect, url_for, session, flash
from sqlalchemy import text
from database import db, Customer, Order, Product, OrderDetail, Batch, SalesRep, User, Commission, RepStock, ToVisit, \
    Expenses
from functools import wraps
from flask_migrate import Migrate
import secrets
import os, csv
from sqlalchemy.exc import SQLAlchemyError
from functools import wraps
from sqlalchemy.sql import func




app = Flask(__name__)

# Configure logging
def setup_logging():
    # Create a log file handler with rotation
    handler = RotatingFileHandler(
        'app.log',  # Log file name
        maxBytes=1024 * 1024,  # 1 MB per file
        backupCount=10  # Keep up to 10 backup files
    )
    handler.setLevel(logging.INFO)  # Log level (INFO, WARNING, ERROR, etc.)
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
    )
    handler.setFormatter(formatter)

    # Add the handler to the Flask app logger
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

# Initialize logging
setup_logging()

secret_key = secrets.token_hex(16)  # Generates a secure random key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_fallback_key')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/momou/Desktop/Food Distribution/db/food_distribution.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database with the app
db.init_app(app)
# Initialize Flask-Migrate
migrate = Migrate(app, db)


@app.route('/set_language/<language>')
def set_language(language):
    if language in ['en', 'ar']:  # Ensure the language is supported
        session['language'] = language
    return redirect(request.referrer or url_for('home'))  # Redirect back to the previous page
# @app.route('/set_language/<language>')
# def set_language(language):
#     if language in translations:
#         session['language'] = language
#     return redirect(request.referrer or url_for('home'))

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session:
                return "Unauthorized: Please log in.", 403

            # Define role hierarchy
            role_hierarchy = {
                'admin': ['admin', 'manager', 'sales', 'inventory', 'delivery', 'support', 'viewer'],
                'manager': ['manager', 'sales', 'inventory', 'delivery', 'support', 'viewer'],
                'sales': ['sales'],
                'inventory': ['inventory'],
                'delivery': ['delivery'],
                'support': ['support'],
                'viewer': ['viewer']
            }

            # Get the user's role and its allowed roles
            user_role = session['role']
            user_allowed_roles = role_hierarchy.get(user_role, [])

            # Check if any of the allowed roles match the user's allowed roles
            if not any(role in user_allowed_roles for role in allowed_roles):
                return f"Unauthorized: You do not have permission to access this page. Required roles: {', '.join(allowed_roles)}", 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def organization_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'organization_id' not in session:
            return abort(403, "Unauthorized: Organization ID missing")
        return f(*args, **kwargs)
    return decorated_function


@app.route('/customers', methods=['GET', 'POST'])
@login_required
@organization_required
def customers():
    try:
        language = session.get('language', 'en')

        # Initialize variables for filtering and searching
        street_name = request.args.get('street_name', '').strip()
        district = request.args.get('district', '').strip()
        search_query = request.form.get('search_query', '').strip()
        search_criteria = request.form.get('search_criteria', 'Store Name').strip()

        # Build the base query
        query = Customer.query

        # Apply filters (from query parameters)
        if street_name:
            query = query.filter(Customer.StreetName.like(f"%{street_name}%"))
        if district:
            query = query.filter(Customer.District.like(f"%{district}%"))

        # Apply search (from form submission)
        if request.method == 'POST' and search_query:
            if search_criteria == "Store Name":
                query = query.filter(Customer.StoreName.like(f"%{search_query}%"))
            elif search_criteria == "District":
                query = query.filter(Customer.District.like(f"%{search_query}%"))
            elif search_criteria == "Street Name":
                query = query.filter(Customer.StreetName.like(f"%{search_query}%"))

        # Execute the query
        customers = query.filter_by(OrganizationID=session['organization_id']).all()

        return render_template(
            'customers.html',
            customers=customers,
            street_name=street_name,
            district=district,
            search_query=search_query,
            search_criteria=search_criteria
        )
    except Exception as e:
        print(f"Error: {e}")
        return f"Error accessing database: {e}"


@app.route('/add_customer', methods=['GET', 'POST'])
@login_required
@organization_required
def add_customer():
    if request.method == 'POST':
        try:
            store_name = request.form['store_name']
            street_name = request.form['street_name']
            district = request.form['district']
            contact_person = request.form['contact_person']
            contact_phone = request.form['contact_phone']
            location = request.form['location']
            notes = request.form['notes']

            new_customer = Customer(
                StoreName=store_name,
                StreetName=street_name,
                District=district,
                ContactPerson=contact_person,
                ContactPhone=contact_phone,
                Location=location,
                Notes=notes,
                OrganizationID=session['organization_id']
            )
            db.session.add(new_customer)
            db.session.commit()

            # Log successful customer creation
            app.logger.info(f"New customer added: {store_name} (ID: {new_customer.CustomerID}) by user {session.get('user_id')}.")
            return redirect('/customers')
        except Exception as e:
            # Log the error
            app.logger.error(f"Error adding customer: {str(e)}", exc_info=True)
            return f"An error occurred while adding the customer: {str(e)}", 500

    # Debugging: Print the current language
    language = session.get('language', 'en')
    app.logger.debug(f"Current language: {language}")  # Log for debugging

    return render_template('add_customer.html')


@app.route('/orders', methods=['GET'])
@app.route('/orders/<int:customer_id>', methods=['GET'])
@login_required
@organization_required
def view_orders(customer_id=None):
    customer = Customer.query.get(customer_id) if customer_id else None

    # Get logged-in user's role
    user_role = session.get('role')
    user_id = session.get('user_id')

    if user_role == 'sales':
        # Fetch the SalesRep ID for the logged-in user
        sales_rep = SalesRep.query.filter_by(UserID=user_id).first()
        if not sales_rep:
            return "Unauthorized: You are not assigned as a sales rep.", 403

        # Fetch orders for this sales rep, including customer name
        if customer_id:
            orders = db.session.query(
                Order, Customer.StoreName, User.Username
            ).join(
                Customer, Order.CustomerID == Customer.CustomerID
            ).join(
                SalesRep, Order.SalesRepID == SalesRep.RepID
            ).join(
                User, SalesRep.UserID == User.UserID
            ).filter(
                Order.CustomerID == customer_id,
                Order.SalesRepID == sales_rep.RepID,
                Customer.OrganizationID == session['organization_id']
            ).all()
        else:
            orders = db.session.query(
                Order, Customer.StoreName, User.Username
            ).join(
                Customer, Order.CustomerID == Customer.CustomerID
            ).join(
                SalesRep, Order.SalesRepID == SalesRep.RepID
            ).join(
                User, SalesRep.UserID == User.UserID
            ).filter(
                Order.SalesRepID == sales_rep.RepID,
                Customer.OrganizationID == session['organization_id']
            ).all()
    elif user_role == 'admin':
        # Admin can see all orders, including customer name
        if customer_id:
            orders = db.session.query(
                Order, Customer.StoreName, User.Username
            ).join(
                Customer, Order.CustomerID == Customer.CustomerID
            ).join(
                SalesRep, Order.SalesRepID == SalesRep.RepID, isouter=True
            ).join(
                User, SalesRep.UserID == User.UserID, isouter=True
            ).filter(
                Order.CustomerID == customer_id,
                Customer.OrganizationID == session['organization_id']
            ).all()
        else:
            orders = db.session.query(
                Order, Customer.StoreName, User.Username
            ).join(
                Customer, Order.CustomerID == Customer.CustomerID
            ).join(
                SalesRep, Order.SalesRepID == SalesRep.RepID, isouter=True
            ).join(
                User, SalesRep.UserID == User.UserID, isouter=True
            ).filter(
                Customer.OrganizationID == session['organization_id']  # Ensuring same organization
            ).all()
    else:
        return "Unauthorized: You do not have permission to view this page.", 403

    # Render the orders page
    return render_template('view_orders.html', customer=customer, orders=orders)



@app.route('/view_order_details/<int:order_id>')
@login_required
@organization_required
def view_order_details(order_id):
    # Fetch the order
    order = db.session.query(Order).join(Customer).filter(
        Order.OrderID == order_id,
        Customer.OrganizationID == session['organization_id']
    ).first_or_404()

    # Fetch all order details associated with the order
    order_details = db.session.query(OrderDetail).join(Order).join(Customer).filter(
        OrderDetail.OrderID == order_id,
        Customer.OrganizationID == session['organization_id']
    ).all()

    # Pass the data to the template
    return render_template('view_order_details.html', order=order, order_details=order_details)



@app.route('/add_order', methods=['GET', 'POST'])
@app.route('/add_order/<int:customer_id>', methods=['GET', 'POST'])
@login_required
@organization_required
def add_order(customer_id=None):
    if session.get('role') not in ['sales', 'admin']:
        app.logger.warning(f"Unauthorized access attempt to add_order by user {session.get('user_id')}.")
        return "Unauthorized: Only sales reps or admins can create orders.", 403

    # If the user is a sales rep, fetch their details
    rep = SalesRep.query.filter_by(UserID=session['user_id']).first() if session.get('role') == 'sales' else None

    # Fetch available products
    products = Product.query.filter_by(OrganizationID=session['organization_id']).all()

    # Fetch customer details if customer_id is provided, otherwise prepare for customer selection
    customer = Customer.query.get(customer_id) if customer_id else None
    customers = Customer.query.filter_by(OrganizationID=session['organization_id']).all() if not customer else []
    app.logger.debug(f"Fetched {len(customers)} customers for order creation.")

    if request.method == 'POST':
        try:
            # If no customer is pre-selected, get customer ID from the form
            if not customer:
                customer_id = int(request.form.get('customer_id'))
                customer = Customer.query.get_or_404(customer_id)

            # Get form data
            product_ids = request.form.getlist('product[]')
            quantities = request.form.getlist('quantity[]')
            prices = request.form.getlist('price_per_unit[]')

            # Validate data
            if not (product_ids and quantities and prices):
                app.logger.warning("Invalid order data submitted: Missing product, quantity, or price.")
                return "Invalid data. Please ensure all fields are filled.", 400

            # Calculate total amount
            total_amount = sum(float(q) * float(p) for q, p in zip(quantities, prices))

            # Create the order but do not commit yet
            new_order = Order(
                CustomerID=customer_id,
                TotalAmount=total_amount,
                SalesRepID=rep.RepID if rep else None,
                OrderDate=datetime.utcnow()
            )
            db.session.add(new_order)

            # Validate and deduct stock
            for product_id, quantity, price in zip(product_ids, quantities, prices):
                product_id = int(product_id)
                quantity = float(quantity)
                price = float(price)

                if rep:
                    # Deduct from the sales rep's assigned stock
                    assigned_stock = RepStock.query.filter_by(SalesRepID=rep.RepID, ProductID=product_id).first()
                    if not assigned_stock or assigned_stock.Quantity < quantity:
                        db.session.rollback()
                        app.logger.error(f"Insufficient stock for product ID {product_id} in assigned inventory.")
                        return f"Error: Insufficient stock for product ID {product_id} in assigned inventory.", 400
                    assigned_stock.Quantity -= quantity
                    db.session.add(assigned_stock)
                    app.logger.info(f"Deducted {quantity} units of product ID {product_id} from sales rep's stock.")
                else:
                    # Deduct from global stock (admin user)
                    remaining_quantity = quantity
                    while remaining_quantity > 0:
                        batch = Batch.query.filter_by(ProductID=product_id).filter(Batch.Quantity > 0).order_by(Batch.PurchaseDate).first()
                        if not batch:
                            db.session.rollback()
                            app.logger.error(f"Not enough stock for product ID {product_id}.")
                            return f"Error: Not enough stock for product ID {product_id}.", 400
                        if batch.Quantity >= remaining_quantity:
                            batch.Quantity -= remaining_quantity
                            remaining_quantity = 0
                        else:
                            remaining_quantity -= batch.Quantity
                            batch.Quantity = 0
                        db.session.add(batch)
                        app.logger.info(f"Deducted {quantity} units of product ID {product_id} from global stock.")

                # Add order detail for the product
                order_detail = OrderDetail(
                    OrderID=new_order.OrderID,
                    ProductID=product_id,
                    Quantity=quantity,
                    PricePerUnit=price
                )
                db.session.add(order_detail)

            # Update sales rep's TotalSales
            if rep:
                rep.TotalSales = (rep.TotalSales or 0.0) + total_amount
                db.session.add(rep)
                app.logger.info(f"Updated sales rep's total sales to {rep.TotalSales}.")

            # Commit all changes if everything is valid
            db.session.commit()
            app.logger.info(f"Order created successfully for customer ID {customer_id} with total amount {total_amount}.")
            return redirect(url_for('view_orders', customer_id=customer_id))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error while creating order: {str(e)}", exc_info=True)
            return f"Database error: {str(e)}", 500

    return render_template('add_order.html', customer=customer, customers=customers, products=products)


# @app.route('/add_order', methods=['GET', 'POST'])
# @app.route('/add_order/<int:customer_id>', methods=['GET', 'POST'])
# @login_required
# def add_order(customer_id=None):
#     if session.get('role') not in ['sales', 'admin']:
#         return "Unauthorized: Only sales reps or admins can create orders.", 403
#
#     # Fetch data
#     rep = SalesRep.query.filter_by(UserID=session['user_id']).first() if session.get('role') == 'sales' else None
#     products = Product.query.filter_by(OrganizationID=session['organization_id']).all()
#     customer = Customer.query.get(customer_id) if customer_id else None
#     customers = Customer.query.filter_by(OrganizationID=session['organization_id']).all() if not customer else []
#
#     if request.method == 'POST':
#         try:
#             # If no customer is pre-selected, get customer ID from the form
#             if not customer:
#                 customer_id = int(request.form.get('customer_id'))
#                 customer = Customer.query.get_or_404(customer_id)
#
#             # Extract order details
#             product_ids = request.form.getlist('product[]')
#             quantities = request.form.getlist('quantity[]')
#             prices = request.form.getlist('price_per_unit[]')
#             print("Customer ID:", customer_id)
#             print("Products:", product_ids)
#             print("Quantities:", quantities)
#             print("Prices:", prices)
#
#             # Validate form inputs
#             if not product_ids or not quantities or not prices:
#                 flash('Please fill out all required fields.', 'danger')
#                 return redirect(url_for('add_order'))
#
#             total_amount = sum(float(q) * float(p) for q, p in zip(quantities, prices))
#
#             # Create the order
#             new_order = Order(
#                 CustomerID=customer_id,
#                 TotalAmount=total_amount,
#                 SalesRepID=rep.RepID if rep else None,
#                 OrderDate=datetime.utcnow()
#             )
#             db.session.add(new_order)
#
#             # Process stock and create order details
#             for product_id, quantity, price in zip(product_ids, quantities, prices):
#                 process_order_stock(product_id, float(quantity), float(price), new_order.OrderID, rep)
#
#             # Update sales rep's sales
#             if rep:
#                 rep.TotalSales = (rep.TotalSales or 0.0) + total_amount
#                 db.session.add(rep)
#
#             db.session.commit()
#             flash('Order added successfully!', 'success')
#             return redirect(url_for('view_orders', customer_id=customer_id))
#         except Exception as e:
#             db.session.rollback()
#             app.logger.error(f"Error adding order: {str(e)}")
#             flash('An error occurred while processing the order.', 'danger')
#
#     return render_template('add_order.html', customer=customer, customers=customers, products=products)
#
#
# def process_order_stock(product_id, quantity, price, order_id, rep):
#     """Handle stock deduction and order detail creation."""
#     if rep:
#         # Deduct from rep's stock
#         assigned_stock = RepStock.query.filter_by(SalesRepID=rep.RepID, ProductID=product_id).first()
#         if not assigned_stock or assigned_stock.Quantity < quantity:
#             raise ValueError(f"Insufficient stock for product ID {product_id}.")
#         assigned_stock.Quantity -= quantity
#         db.session.add(assigned_stock)
#     else:
#         # Deduct from global stock (admin)
#         remaining_quantity = quantity
#         while remaining_quantity > 0:
#             batch = Batch.query.filter_by(ProductID=product_id).filter(Batch.Quantity > 0).order_by(Batch.PurchaseDate).first()
#             if not batch:
#                 raise ValueError(f"Not enough stock for product ID {product_id}.")
#             if batch.Quantity >= remaining_quantity:
#                 batch.Quantity -= remaining_quantity
#                 remaining_quantity = 0
#             else:
#                 remaining_quantity -= batch.Quantity
#                 batch.Quantity = 0
#             db.session.add(batch)
#
#     # Add order detail
#     order_detail = OrderDetail(OrderID=order_id, ProductID=product_id, Quantity=quantity, PricePerUnit=price)
#     db.session.add(order_detail)





@app.route('/inventory')
@login_required
@organization_required
@role_required(['admin', 'manager', 'inventory'])
def view_inventory():
    # Set the low stock threshold
    LOW_STOCK_THRESHOLD = 5

    # Fetch all products and their batch details, if any
    products = db.session.query(
        Product.ProductID,
        Product.ProductName,
        db.func.coalesce(Batch.BatchID, None).label('BatchID'),
        db.func.coalesce(Batch.Quantity, 0).label('Quantity'),
        db.func.coalesce(Batch.PurchasePrice, 0).label('PurchasePrice'),
        db.func.coalesce(Batch.PurchaseDate, None).label('PurchaseDate'),
        (db.func.coalesce(Batch.Quantity, 0) < LOW_STOCK_THRESHOLD).label('is_low_stock')
    ).outerjoin(Batch, Product.ProductID == Batch.ProductID).all()

    return render_template('inventory.html', products=products)




@app.route('/delete_order/<int:order_id>', methods=['POST'])
@login_required
@organization_required
@role_required(['admin'])
def delete_order(order_id):
    try:
        # Find the order by ID
        order = db.session.query(Order).join(Customer).filter(
            Order.OrderID == order_id,
            Customer.OrganizationID == session['organization_id']
        ).first_or_404()
        sales_rep = SalesRep.query.filter_by(RepID=order.SalesRepID).first()

        if sales_rep:
            sales_rep.TotalSales = (sales_rep.TotalSales or 0.0) - (order.TotalAmount or 0.0)
            db.session.add(sales_rep)
            app.logger.info(f"Adjusted sales rep's total sales after deleting order ID {order_id}.")

        # Delete related order details first
        OrderDetail.query.filter_by(OrderID=order_id).delete()

        # Delete the order itself
        db.session.delete(order)
        db.session.commit()

        app.logger.info(f"Order ID {order_id} deleted successfully by user {session.get('user_id')}.")
        return redirect(url_for('view_orders', customer_id=order.CustomerID))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting order ID {order_id}: {str(e)}", exc_info=True)
        return f"An error occurred while deleting the order: {str(e)}", 500

@app.route('/add_stock/<int:product_id>', methods=['POST', 'GET'])
@login_required
@organization_required
def add_stock(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        try:
            quantity = request.form['quantity']
            purchase_price = request.form['purchase_price']

            new_batch = Batch(
                ProductID=product_id,
                Quantity=int(quantity),
                PurchasePrice=float(purchase_price),
                PurchaseDate=datetime.now().date()
            )
            db.session.add(new_batch)
            db.session.commit()

            app.logger.info(f"Added {quantity} units of product ID {product_id} to stock.")
            return redirect(url_for('view_inventory'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding stock for product ID {product_id}: {str(e)}", exc_info=True)
            return f"An error occurred while adding stock: {str(e)}", 500

    return render_template('add_stock.html', product=product)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.session.execute(
            text("SELECT * FROM Users WHERE Username = :username"),
            {"username": username}
        ).mappings().first()

        if user and check_password_hash(user['Password'], password):
            session['user_id'] = user['UserID']
            session['role'] = user['Role']  # Store the role in the session
            app.logger.info(f"User {username} logged in successfully.")
            session['organization_id'] = user.get('OrganizationID', None)  # Fetch organization ID
            return redirect(url_for('customers'))  # Redirect to a protected page
        else:
            app.logger.warning(f"Failed login attempt for username: {username}.")
            return "Invalid username or password", 401

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])  # Only admin can access this route
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')  # Default role is 'user'

        # Handle commission rate and monthly target for sales reps
        commission_rate = request.form.get('commission_rate', 0.03)  # Default is 3%
        monthly_target = request.form.get('monthly_target', 65000)  # Default is 65000 SAR

        try:
            commission_rate = float(commission_rate) if role == 'sales' else None
            monthly_target = float(monthly_target) if role == 'sales' else None
        except ValueError:
            commission_rate = 0.03  # Fallback to default
            monthly_target = 65000  # Fallback to default

        if commission_rate < 0 or commission_rate > 100:
            return "Error: Commission rate must be between 0 and 100.", 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            # Insert user into Users table
            db.session.execute(
                text(
                    "INSERT INTO Users (Username, Password, Role, OrganizationID) VALUES (:username, :password, :role, :org_id)"),
                {"username": username, "password": hashed_password, "role": role, "org_id": session['organization_id']}
            )
            db.session.commit()

            # Fetch the newly added user's ID
            user = db.session.execute(
                text("SELECT * FROM Users WHERE Username = :username"),
                {"username": username}
            ).mappings().first()

            # If the role is 'sales', add an entry to the SalesRep table
            if role == 'sales':
                db.session.execute(
                    text(
                        "INSERT INTO SalesReps (UserID, MonthlyTarget, CommissionRate, OrganizationID) VALUES (:user_id, :target, :rate, :org_id)"),
                    {
                        "user_id": user['UserID'],
                        "target": monthly_target, "rate":
                        commission_rate / 100,
                        "org_id": session['organization_id']}
                )
                db.session.commit()

            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error: {e}")
            return f"Error registering user: {e}"

    return render_template('register.html')



@app.route('/logout')
@login_required
@organization_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/static/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')


@app.route('/')
@login_required
@organization_required
def index():
    if session.get('role') == 'admin':
        # Fetch key metrics for admin
        total_customers = db.session.query(Customer).count()
        total_orders = db.session.query(Order).join(Customer).filter(
            Customer.OrganizationID == session['organization_id']
        ).count()
        low_stock_products = db.session.query(Product).join(Batch).filter(Batch.Quantity < 5).all()

        # Calculate net profit
        total_revenue = db.session.query(db.func.sum(Order.TotalAmount)).scalar() or 0.0
        total_expenses = db.session.query(db.func.sum(Expenses.Amount)).scalar() or 0.0
        net_profit = total_revenue - total_expenses

        return render_template(
            'index.html',
            total_customers=total_customers,
            total_orders=total_orders,
            low_stock_products=low_stock_products,
            assigned_stock=None,  # Admin doesn't need this
            to_visit_list=None,  # Admin doesn't need this
            net_profit=net_profit  # Pass net profit to the template
        )
    elif session.get('role') == 'sales':
        # Fetch key metrics for sales reps
        sales_rep = SalesRep.query.filter_by(UserID=session['user_id']).first()
        assigned_stock = db.session.query(RepStock).filter_by(SalesRepID=sales_rep.RepID).count() if sales_rep else 0
        to_visit_list = db.session.query(ToVisit).filter_by(rep_id=session['user_id']).all()

        return render_template(
            'index.html',
            total_customers=None,  # Sales reps don't need this
            total_orders=None,  # Sales reps don't need this
            low_stock_products=None,  # Sales reps don't need this
            assigned_stock=assigned_stock,
            to_visit_list=to_visit_list,
            net_profit=None  # Sales reps don't need this
        )
    else:
        return "Unauthorized: Your role is not supported.", 403


@app.route('/dashboard')
@organization_required
@login_required
def dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif session.get('role') == 'sales':
        return redirect(url_for('sales_rep_dashboard'))
    else:
        return "Unauthorized: You do not have access to any dashboard.", 403

@app.route('/admin_dashboard')
@login_required
@organization_required
@role_required(['admin'])  # Restrict to admin only
def admin_dashboard():
    # Fetch key metrics
    total_customers = db.session.query(Customer).count()
    total_orders = db.session.query(Order).count()
    total_products = db.session.query(Product).count()
    total_revenue = db.session.query(db.func.sum(Order.TotalAmount)).scalar() or 0.0


    # Fetch low stock products
    low_stock_products = db.session.query(Product).join(Batch).filter(Batch.Quantity < 5).all()

    # Fetch current stock assignments for all sales reps
    rep_stock_details = get_rep_stock_details()

    # Recent Activity (Example: Last 5 Orders)
    recent_activities = []
    orders = db.session.query(Order, Customer).join(Customer, Order.CustomerID == Customer.CustomerID).order_by(
        Order.OrderDate.desc()).limit(5).all()

    for order, customer in orders:
        recent_activities.append({
            "action": "Order Placed",
            "details": f"Order #{order.OrderID} for {customer.StoreName} (Customer ID: {customer.CustomerID})",
            "timestamp": order.OrderDate,
        })

    # Sales Chart Data
    sales_data = db.session.query(
        db.func.strftime('%Y-%m', Order.OrderDate).label('month'),
        db.func.sum(Order.TotalAmount).label('total')
    ).group_by('month').order_by('month').all()

    sales_chart = {
        'labels': [data.month for data in sales_data],
        'data': [data.total for data in sales_data]
    }

    total_visits = ToVisit.query.count()
    pending_visits = ToVisit.query.filter_by(status='Pending').count()
    today_visits = ToVisit.query.filter(ToVisit.visit_date == date.today()).count()
    completed_visits = ToVisit.query.filter(ToVisit.status == 'Completed').count()


    return render_template('admin_dashboard.html',
                          total_customers=total_customers,
                          total_orders=total_orders,
                          total_products=total_products,
                           total_revenue=total_revenue,
                           low_stock_products=low_stock_products,
                          rep_stock_details=rep_stock_details,
                           total_visits=total_visits,
                           pending_visits=pending_visits,
                           today_visits=today_visits,
                           completed_visits=completed_visits,
                           recent_activities=recent_activities,
                           sales_chart=sales_chart

                           )




@app.route('/manage_users')
@login_required
@organization_required
@role_required(['admin'])  # Only admin can access
def manage_users():
    users = db.session.execute(text("SELECT * FROM Users")).fetchall()
    return render_template('manage_users.html', users=users)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])  # Only admin can access
def edit_user(user_id):
    user = db.session.execute(
        text("SELECT * FROM Users WHERE UserID = :user_id"),
        {"user_id": user_id}
    ).mappings().first()

    if not user:
        return "User not found.", 404

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        new_password = request.form['new_password']

        # Update username and role
        db.session.execute(
            text("UPDATE Users SET Username = :username, Role = :role WHERE UserID = :user_id"),
            {"username": username, "role": role, "user_id": user_id}
        )

        # Update password if a new one is provided
        if new_password:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.execute(
                text("UPDATE Users SET Password = :password WHERE UserID = :user_id"),
                {"password": hashed_password, "user_id": user_id}
            )

        db.session.commit()
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@organization_required
@role_required(['admin'])  # Only admin can access
def delete_user(user_id):
    db.session.execute(
        text("DELETE FROM Users WHERE UserID = :user_id"),
        {"user_id": user_id}
    )
    db.session.commit()
    return redirect(url_for('manage_users'))


@app.route('/sales_rep_dashboard')
@login_required
@organization_required
def sales_rep_dashboard():
    # Ensure the logged-in user has the correct role
    if session.get('role') != 'sales':  # Check for 'sales' role
        return "Unauthorized: Only sales reps can access this page.", 403

    # Fetch the SalesRep record based on the UserID stored in the session
    sales_rep = SalesRep.query.filter_by(UserID=session['user_id']).first()

    if not sales_rep:
        return "Error: SalesRep record not found for the logged-in user.", 403

    sales_rep_id = sales_rep.RepID

    # Query to get total sales for this month by the sales rep
    total_sales = (
        db.session.query(func.sum(Order.TotalAmount))
        .filter(Order.SalesRepID == sales_rep_id)
        .filter(func.strftime('%Y', Order.OrderDate) == datetime.now().strftime('%Y'))
        .filter(func.strftime('%m', Order.OrderDate) == datetime.now().strftime('%m'))
        .scalar()
    ) or 0.0

    # Calculate commission earned for the sales rep
    commission_earned = calculate_commission(sales_rep_id)

    # Query to get all orders for this month by the sales rep
    orders = (
        db.session.query(Order)
        .filter(Order.SalesRepID == sales_rep_id)
        .filter(func.strftime('%Y-%m', Order.OrderDate) == datetime.now().strftime('%Y-%m'))
        .all()
    )

    # Fetch assigned stock for the sales rep
    assigned_stock = db.session.query(RepStock).filter_by(SalesRepID=sales_rep_id).all()

    return render_template(
        'sales_rep_dashboard.html',
        total_sales=total_sales,
        commission_earned=commission_earned,
        orders=orders,
        assigned_stock=assigned_stock,  # Pass assigned stock to the template
    )




@app.route('/add_order_from_dashboard', methods=['POST'])
@login_required
@organization_required
@role_required(['sales'])  # Only sales reps can access
def add_order_from_dashboard():
    customer_id = request.form['customer_id']
    product_id = request.form['product_id']
    quantity = int(request.form['quantity'])
    price = float(request.form['price'])

    # Calculate total amount
    total_amount = quantity * price

    # Create and save the order
    new_order = Order(
        CustomerID=customer_id,
        TotalAmount=total_amount,
        SalesRepID=session['user_id'],  # Ensure the sales rep is linked
        OrderDate=datetime.utcnow()
    )
    db.session.add(new_order)
    db.session.commit()

    # Add order details
    order_detail = OrderDetail(
        OrderID=new_order.OrderID,
        ProductID=product_id,
        Quantity=quantity,
        PricePerUnit=price
    )
    db.session.add(order_detail)

    # Update inventory
    product = Product.query.get(product_id)
    product.Quantity -= quantity
    db.session.add(product)
    db.session.commit()

    return redirect(url_for('sales_rep_dashboard'))

@app.route('/sales_reps', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])
def manage_sales_reps():
    if request.method == 'POST':
        user_id = request.form['user_id']
        target = float(request.form.get('monthly_target', 65000))
        rate = float(request.form.get('commission_rate', 0.03))

        # Create a new sales rep
        new_rep = SalesRep(UserID=user_id, MonthlyTarget=target, CommissionRate=rate)
        db.session.add(new_rep)
        db.session.commit()
        return redirect(url_for('manage_sales_reps'))

    # Fetch all sales reps
    sales_reps = db.session.query(SalesRep, User).join(User, SalesRep.UserID == User.UserID).all()
    return render_template('sales_reps.html', sales_reps=sales_reps)

def calculate_commission(sales_rep_id):
    # Fetch the sales rep
    rep = SalesRep.query.filter_by(RepID=sales_rep_id).first()
    print(f"DEBUG: SalesRep fetched: {rep}")
    if not rep:
        print(f"DEBUG: No SalesRep found with ID {sales_rep_id}")
        return 0.0  # Return 0 if the sales rep doesn't exist

    # Fetch all orders for the sales rep and calculate total sales
    orders = Order.query.filter_by(SalesRepID=rep.RepID).all()
    total_sales = sum(order.TotalAmount or 0 for order in orders)  # Handle None values
    print(f"DEBUG: Total Sales for SalesRep {sales_rep_id}: {total_sales}")

    # Debugging output
    print(f"DEBUG: SalesRep ID: {rep.RepID}")
    print(f"DEBUG: Total Orders: {len(orders)}")
    print(f"DEBUG: Total Sales: {total_sales}")

    # Check if the target was met and calculate commission
    commission_earned = (
        total_sales * rep.CommissionRate if total_sales >= rep.MonthlyTarget else 0
    )

    # Debugging output
    print(f"DEBUG: Commission Earned: {commission_earned}")

    # Store commission data
    commission = Commission(
        RepID=rep.RepID,
        Month=datetime.utcnow().strftime('%Y-%m'),
        TotalSales=total_sales,
        CommissionEarned=commission_earned
    )
    db.session.add(commission)
    db.session.commit()

    return commission_earned  # Return the calculated commission



@app.route('/order/<int:order_id>/add_product', methods=['GET', 'POST'])
@login_required
@organization_required
def add_product_to_order(order_id):
    # Fetch the order details
    order = Order.query.get_or_404(order_id)

    if request.method == 'POST':
        # Get product and quantity from the form
        product_id = request.form['product_id']
        quantity = int(request.form['quantity'])

        # Fetch the product details
        product = Product.query.get_or_404(product_id)

        # Calculate the price per unit
        price_per_unit = product.BasePrice

        # Add order detail
        order_detail = OrderDetail(
            OrderID=order.OrderID,
            ProductID=product_id,
            Quantity=quantity,
            PricePerUnit=price_per_unit,
        )
        db.session.add(order_detail)
        db.session.commit()

        return redirect(url_for('view_order_details', order_id=order_id))

    # Fetch all products for selection
    products = Product.filter_by(OrganizationID=session['organization_id']).all()
    return render_template('add_product_to_order.html', order=order, products=products)

from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

@app.route('/edit_order/<int:order_id>', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])
def edit_order(order_id):
    try:
        # Fetch the order and its details
        order = db.session.query(Order).join(Customer).filter(
            Order.OrderID == order_id,
            Customer.OrganizationID == session['organization_id']
        ).first_or_404()
        order_details = db.session.query(OrderDetail).join(Order).join(Customer).filter(
            OrderDetail.OrderID == order_id,
            Customer.OrganizationID == session['organization_id']
        ).all()
        products = Product.filter_by(OrganizationID=session['organization_id']).all()

        if request.method == 'POST':
            # Fetch updated data from the form
            updated_products = request.form.getlist('product[]')
            updated_quantities = request.form.getlist('quantity[]')
            updated_prices = request.form.getlist('price_per_unit[]')

            # Validate data
            if not (updated_products and updated_quantities and updated_prices):
                db.session.rollback()
                app.logger.warning("Invalid data submitted for editing order.")
                return "Invalid data. Ensure all fields are filled.", 400

            # Step 1: Reverse changes from the current order (add back stock)
            for detail in order_details:
                batches = (
                    Batch.query.filter_by(ProductID=detail.ProductID)
                    .filter(Batch.Quantity > 0)
                    .order_by(Batch.PurchaseDate.desc())
                    .with_for_update()
                    .all()
                )
                remaining_to_add = detail.Quantity
                for batch in batches:
                    if remaining_to_add <= 0:
                        break
                    add_amount = min(remaining_to_add, batch.Quantity)  # Add back up to the batch's current quantity
                    batch.Quantity += add_amount
                    remaining_to_add -= add_amount
                db.session.add_all(batches)

            # Step 2: Delete existing order details
            OrderDetail.query.filter_by(OrderID=order_id).delete()

            # Step 3: Update order details with the new data and deduct stock
            total_amount = 0
            for product_id, quantity, price in zip(updated_products, updated_quantities, updated_prices):
                product_id = int(product_id)
                quantity = int(quantity)
                price = float(price)
                total_amount += quantity * price

                # Deduct inventory for the new quantities
                remaining_quantity = quantity
                batches = (
                    Batch.query.filter_by(ProductID=product_id)
                    .filter(Batch.Quantity > 0)
                    .order_by(Batch.PurchaseDate)
                    .with_for_update()
                    .all()
                )
                if not batches or sum(batch.Quantity for batch in batches) < remaining_quantity:
                    db.session.rollback()
                    app.logger.error(f"Not enough stock for product ID {product_id}.")
                    return f"Error: Not enough stock for Product ID {product_id}.", 400

                for batch in batches:
                    if remaining_quantity <= 0:
                        break
                    deduct_amount = min(remaining_quantity, batch.Quantity)
                    batch.Quantity -= deduct_amount
                    remaining_quantity -= deduct_amount
                    db.session.add(batch)

                # Create new order detail
                order_detail = OrderDetail(
                    OrderID=order.OrderID,
                    ProductID=product_id,
                    Quantity=quantity,
                    PricePerUnit=price
                )
                db.session.add(order_detail)

            # Step 4: Update order total
            order.TotalAmount = total_amount
            db.session.add(order)

            # Commit all changes
            db.session.commit()
            app.logger.info(f"Order ID {order_id} edited successfully by user {session.get('user_id')}.")
            return redirect(url_for('view_order_details', order_id=order_id))
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error while editing order ID {order_id}: {str(e)}", exc_info=True)
        return f"Database error: {str(e)}", 500
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error editing order ID {order_id}: {str(e)}", exc_info=True)
        return f"Error editing order: {str(e)}", 500
    return render_template('edit_order.html', order=order, order_details=order_details, products=products)

@app.route('/assign_stock', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])
def assign_stock():
    sales_reps = SalesRep.query.filter_by(OrganizationID=session['organization_id']).all()
    products = Product.query.filter_by(OrganizationID=session['organization_id']).all()
    if request.method == 'POST':
        try:
            sales_rep_id = request.form['sales_rep']
            product_id = request.form['product']
            quantity = int(request.form['quantity'])

            # Check if sufficient stock is available
            total_stock = db.session.query(
                db.func.sum(Batch.Quantity)
            ).filter(
                Batch.ProductID == product_id,
                Batch.OrganizationID == session['organization_id']
            ).scalar() or 0

            if total_stock < quantity:
                return "Error: Not enough stock available to assign.", 400

            # Calculate the weighted average cost of the assigned stock
            assigned_cost = 0
            remaining_quantity = quantity
            while remaining_quantity > 0:
                batch = Batch.query.filter_by(ProductID=product_id).filter(Batch.Quantity > 0).order_by(Batch.PurchaseDate).first()
                if not batch:
                    raise ValueError("Error: Not enough stock in batches.")

                if batch.Quantity >= remaining_quantity:
                    assigned_cost += remaining_quantity * batch.PurchasePrice
                    batch.Quantity -= remaining_quantity
                    remaining_quantity = 0
                else:
                    assigned_cost += batch.Quantity * batch.PurchasePrice
                    remaining_quantity -= batch.Quantity
                    batch.Quantity = 0
                db.session.add(batch)

            # Update or create RepStock entry
            rep_stock = RepStock.query.filter_by(SalesRepID=sales_rep_id, ProductID=product_id).first()
            if rep_stock:
                rep_stock.Quantity += quantity
                rep_stock.AssignedCost = (rep_stock.AssignedCost or 0) + assigned_cost
            else:
                rep_stock = RepStock(SalesRepID=sales_rep_id, ProductID=product_id, Quantity=quantity, AssignedCost=assigned_cost)
                db.session.add(rep_stock)

            # Commit changes if everything is successful
            db.session.commit()
            return redirect(url_for('assign_stock'))

        except Exception as e:
            # Rollback changes if an error occurs
            db.session.rollback()
            return f"Error during stock assignment: {str(e)}", 500

    # Fetch current stock assignments for all sales reps and calculate profit/loss
    all_rep_stocks = db.session.query(RepStock).filter_by(OrganizationID=session['organization_id']).all()
    rep_stock_details = []
    for stock in all_rep_stocks:
        # Calculate sales revenue for the product assigned to the sales rep
        sales_revenue = db.session.query(
            db.func.sum(OrderDetail.Quantity * OrderDetail.PricePerUnit)
        ).join(Order, Order.OrderID == OrderDetail.OrderID).filter(
            Order.SalesRepID == stock.SalesRepID,
            OrderDetail.ProductID == stock.ProductID
        ).scalar() or 0

        # Calculate profit/loss
        profit_or_loss = sales_revenue - (stock.AssignedCost or 0)

        rep_stock_details.append({
            'rep': stock.sales_rep.user.Username,
            'product': stock.product.ProductName,
            'assigned_quantity': stock.Quantity,
            'assigned_cost': stock.AssignedCost,
            'sales_revenue': sales_revenue,
            'profit_or_loss': profit_or_loss
        })

    return render_template('assign_stock.html', sales_reps=sales_reps, products=products, rep_stock_details=rep_stock_details)


    # Fetch current stock assignments for all sales reps and calculate profit/loss
    all_rep_stocks = db.session.query(RepStock).all()
    rep_stock_details = []
    for stock in all_rep_stocks:
        # Calculate sales revenue for the product assigned to the sales rep
        sales_revenue = db.session.query(
            db.func.sum(OrderDetail.Quantity * OrderDetail.PricePerUnit)
        ).join(Order, Order.OrderID == OrderDetail.OrderID).filter(
            Order.SalesRepID == stock.SalesRepID,
            OrderDetail.ProductID == stock.ProductID
        ).scalar() or 0

        # Calculate profit/loss
        profit_or_loss = sales_revenue - (stock.AssignedCost or 0)

        rep_stock_details.append({
            'rep': stock.sales_rep.user.Username,
            'product': stock.product.ProductName,
            'assigned_quantity': stock.Quantity,
            'assigned_cost': stock.AssignedCost,
            'sales_revenue': sales_revenue,
            'profit_or_loss': profit_or_loss
        })

    # Use reusable function to fetch stock details
    rep_stock_details = get_rep_stock_details()

    return render_template('assign_stock.html', sales_reps=sales_reps, products=products, rep_stock_details=rep_stock_details)


def get_rep_stock_details():
    """Fetch stock assignment details for all sales reps."""
    all_rep_stocks = db.session.query(RepStock).all()
    rep_stock_details = []

    for stock in all_rep_stocks:
        # Calculate sales revenue for the product assigned to the sales rep
        sales_revenue = db.session.query(
            db.func.sum(OrderDetail.Quantity * OrderDetail.PricePerUnit)
        ).join(Order, Order.OrderID == OrderDetail.OrderID).filter(
            Order.SalesRepID == stock.SalesRepID,
            OrderDetail.ProductID == stock.ProductID
        ).scalar() or 0

        # Calculate profit/loss
        profit_or_loss = sales_revenue - (stock.AssignedCost or 0)

        rep_stock_details.append({
            'rep': stock.sales_rep.user.Username,
            'product': stock.product.ProductName,
            'assigned_quantity': stock.Quantity,
            'assigned_cost': stock.AssignedCost or 0,  # Handle None
            'sales_revenue': sales_revenue,
            'profit_or_loss': profit_or_loss
        })

    return rep_stock_details

@app.route('/edit_customer/<int:customer_id>', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    if request.method == 'POST':
        try:
            # Get form data
            customer.StoreName = request.form['store_name']
            customer.StreetName = request.form['street_name']
            customer.District = request.form['district']
            customer.ContactPerson = request.form['contact_person']
            customer.ContactPhone = request.form['contact_phone']
            customer.Location = request.form['location']
            customer.Notes = request.form['notes']

            # Commit changes to the database
            db.session.commit()
            app.logger.info(f"Customer ID {customer_id} edited successfully by user {session.get('user_id')}.")
            return redirect(url_for('customers'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error editing customer ID {customer_id}: {str(e)}", exc_info=True)
            return f"Error updating customer: {str(e)}", 500

    return render_template('edit_customer.html', customer=customer)


@app.route('/add_product', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])
def add_product():
    if request.method == 'POST':
        try:
            product_name = request.form.get('product_name', '').strip()
            base_price = request.form.get('base_price', '').strip()

            # Validate the inputs
            if not product_name:
                app.logger.warning("Product name is required.")
                return "Error: Product name is required.", 400
            try:
                base_price = float(base_price)
            except ValueError:
                app.logger.warning("Invalid base price provided.")
                return "Error: Base price must be a valid number.", 400

            # Create a new Product instance
            new_product = Product(
                ProductName=product_name,
                BasePrice=base_price,
                OrganizationID=session['organization_id']
            )
            db.session.add(new_product)
            db.session.commit()

            app.logger.info(f"New product added: {product_name} (ID: {new_product.ProductID}) by user {session.get('user_id')}.")
            return redirect(url_for('view_inventory'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error adding product: {str(e)}", exc_info=True)
            return f"An error occurred while adding the product: {str(e)}", 500

    return render_template('add_product.html')


@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@organization_required
@role_required(['admin'])
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        try:
            product_name = request.form.get('product_name', '').strip()
            base_price = request.form.get('base_price', '').strip()

            # Validate the inputs
            if not product_name:
                app.logger.warning("Product name is required.")
                return "Error: Product name is required.", 400
            try:
                base_price = float(base_price)
            except ValueError:
                app.logger.warning("Invalid base price provided.")
                return "Error: Base price must be a valid number.", 400

            # Update the product fields
            product.ProductName = product_name
            product.BasePrice = base_price
            db.session.commit()

            app.logger.info(f"Product ID {product_id} edited successfully by user {session.get('user_id')}.")
            return redirect(url_for('inventory'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error editing product ID {product_id}: {str(e)}", exc_info=True)
            return f"Error updating product: {str(e)}", 500

    return render_template('edit_product.html', product=product)

@app.route('/remove_product/<int:product_id>', methods=['POST'])
@login_required
@organization_required
@role_required(['admin'])
def remove_product(product_id):
    try:
        product = Product.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()

        app.logger.info(f"Product ID {product_id} removed successfully by user {session.get('user_id')}.")
        return redirect(url_for('view_inventory'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error removing product ID {product_id}: {str(e)}", exc_info=True)
        return f"An error occurred while trying to remove the product: {str(e)}", 500

@app.route('/to_visit', methods=['GET'])
@login_required
@organization_required
def view_to_visit():
    # Only fetch visits assigned to the logged-in sales rep
    to_visit_list = ToVisit.query.join(Customer).filter(
        ToVisit.rep_id == current_user.id,
        Customer.OrganizationID == session['organization_id']
    ).order_by(ToVisit.visit_date).all()

    return render_template('to_visit.html', to_visit_list=to_visit_list)

@app.route('/add_to_visit/<int:customer_id>', methods=['POST'])
@login_required
@organization_required
def add_to_visit(customer_id):
    visit_date = request.form.get('visit_date')
    notes = request.form.get('notes')

    # Validate inputs
    if not visit_date:
        flash('Visit date is required.', 'danger')
        return redirect(url_for('customers'))

    # Validate the user's session role and ID
    user_id = session.get('user_id')
    user_role = session.get('role')
    if not user_id or user_role not in ['admin', 'sales']:
        flash('Unauthorized: Only admins and sales reps can schedule visits.', 'danger')
        return redirect(url_for('customers'))

    # Create the new visit
    new_visit = ToVisit(
        customer_id=customer_id,
        rep_id=user_id,  # Use session's user_id for the logged-in user
        visit_date=datetime.strptime(visit_date, "%Y-%m-%d"),
        notes=notes
    )
    db.session.add(new_visit)
    db.session.commit()
    flash('Visit scheduled successfully!', 'success')
    return redirect(url_for('customers'))



@app.route('/complete_visit/<int:visit_id>', methods=['POST'])
@login_required
@organization_required
@role_required(['admin', 'sales'])
def complete_visit(visit_id):
    visit = ToVisit.query.get_or_404(visit_id)
    visit.status = 'Completed'
    db.session.commit()
    flash('Visit marked as completed!', 'success')
    return redirect(url_for('monitor_visits'))



@app.route('/monitor_visits', methods=['GET'])
@login_required
@organization_required
@role_required(['admin'])
def monitor_visits():
    query = db.session.query(ToVisit).join(Customer).join(User)

    # Apply filters
    rep = request.args.get('rep')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if rep:
        query = query.filter(User.Username.ilike(f"%{rep}%"))
    if start_date:
        query = query.filter(ToVisit.visit_date >= start_date)
    if end_date:
        query = query.filter(ToVisit.visit_date <= end_date)

    page = request.args.get('page', 1, type=int)
    visits = db.session.query(ToVisit).join(Customer).join(User).order_by(ToVisit.visit_date).paginate(page=page,
                                                                                                       per_page=10)
    return render_template('monitor_visits.html', visits=visits)

@app.route('/delete_batch/<int:batch_id>', methods=['POST'])
@login_required
@organization_required
def delete_batch(batch_id):
    if session.get('role') not in ['admin', 'inventory']:
        app.logger.warning(f"Unauthorized access attempt to delete batch by user {session.get('user_id')}.")
        return "Unauthorized: Only admins or inventory managers can delete batches.", 403

    try:
        batch = Batch.query.get(batch_id)
        if not batch:
            app.logger.warning(f"Batch ID {batch_id} not found.")
            return f"Batch with ID {batch_id} not found.", 404

        db.session.delete(batch)
        db.session.commit()

        app.logger.info(f"Batch ID {batch_id} deleted successfully by user {session.get('user_id')}.")
        flash(f"Batch {batch_id} has been successfully deleted.", "success")
        return redirect(url_for('view_inventory'))
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error deleting batch ID {batch_id}: {str(e)}", exc_info=True)
        return f"An error occurred while trying to delete the batch: {str(e)}", 500

@app.route('/profit_loss', methods=['GET'])
@login_required
@organization_required
def profit_loss():
    # Calculate income from sales (sum of all order totals)
    total_income = db.session.query(func.sum(Order.TotalAmount)).scalar() or 0.0

    # Calculate total expenses
    total_expenses = db.session.query(func.sum(Expenses.Amount)).scalar() or 0.0

    # Calculate net profit or loss
    net_profit_loss = total_income - total_expenses

    # Fetch expenses for reporting
    expenses = Expenses.query.order_by(Expenses.Date.desc()).all()

    # Pass the data to the template
    return render_template('profit_loss.html',
                           total_income=total_income,
                           total_expenses=total_expenses,
                           net_profit_loss=net_profit_loss,
                           expenses=expenses)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
@organization_required
def add_expense():
    if request.method == 'POST':
        description = request.form['description']
        amount = float(request.form['amount'])
        date = request.form['date']
        category = request.form['category']

        # Create a new expense entry
        new_expense = Expenses(
            Description=description,
            Amount=amount,
            Date=date,
            Category=category,
            CreatedBy=session['user_id'],
            OrganizationID=session['organization_id']

        )
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('profit_loss'))

    return render_template('add_expense.html')

# if __name__ == '__main__':
#     app.run(host="0.0.0.0", port=5000, debug=True)

def handler(event, context):
    return app(event, context)

if __name__ == "__main__":
    app.run(debug=True)
