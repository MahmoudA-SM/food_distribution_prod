from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from sqlalchemy import Column, Integer, Date, Text, ForeignKey, String, DateTime

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from sqlalchemy import Float

# Initialize SQLAlchemy
db = SQLAlchemy()

# Define the Customer model
class Customer(db.Model):
    __tablename__ = 'Customers'
    CustomerID = db.Column(db.Integer, primary_key=True)
    StoreName = db.Column(db.String(100), nullable=False)
    StreetName = db.Column(db.String(100), nullable=False)
    District = db.Column(db.String(50), nullable=False)
    ContactPerson = db.Column(db.String(100))
    ContactPhone = db.Column(db.String(20))
    Location = db.Column(db.String(255))
    Notes = db.Column(db.String(255))
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('customers', lazy=True))

class Order(db.Model):
    __tablename__ = 'Orders'
    OrderID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customers.CustomerID'), nullable=False)
    TotalAmount = db.Column(db.Float, nullable=False)
    SalesRepID = db.Column(db.Integer, db.ForeignKey('Users.UserID'), nullable=True)
    OrderDate = db.Column(db.DateTime, default=datetime.utcnow)
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('orders', lazy=True))

    # Relationship to access customer details from an order
    customer = db.relationship('Customer', backref='orders')
    sales_rep = db.relationship('SalesRep', backref='orders')

class Product(db.Model):
    __tablename__ = 'Products'
    ProductID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ProductName = db.Column(db.String(255), nullable=False)
    BasePrice = db.Column(db.Float, nullable=False)
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('products', lazy=True))

class OrderDetail(db.Model):
    __tablename__ = 'OrderDetails'
    DetailID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    OrderID = db.Column(db.Integer, db.ForeignKey('Orders.OrderID'), nullable=False)
    ProductID = db.Column(db.Integer, db.ForeignKey('Products.ProductID'), nullable=False)
    Quantity = db.Column(db.Float, nullable=False)
    PricePerUnit = db.Column(db.Float, nullable=False)
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)

    # Relationships (optional)
    order = db.relationship('Order', backref='order_details')
    product = db.relationship('Product', backref='order_details')
    organization = db.relationship('Organization', backref=db.backref('order_details', lazy=True))


class Batch(db.Model):
    __tablename__ = 'Batches'
    BatchID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ProductID = db.Column(db.Integer, db.ForeignKey('Products.ProductID'), nullable=False)
    Quantity = db.Column(db.Float, nullable=False)
    PurchasePrice = db.Column(db.Float, nullable=False)
    PurchaseDate = db.Column(db.DateTime, default=datetime.utcnow)
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)

    # Relationship to link batches to products
    product = db.relationship('Product', backref='batches')
    organization = db.relationship('Organization', backref=db.backref('batches', lazy=True))


class User(db.Model):
    __tablename__ = 'Users'
    UserID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Username = db.Column(db.String(255), nullable=False, unique=True)
    Password = db.Column(db.String(255), nullable=False)
    Role = db.Column(db.String(50), nullable=False)
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('users', lazy=True))

class SalesRep(db.Model):
    __tablename__ = 'SalesReps'
    RepID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    UserID = db.Column(db.Integer, db.ForeignKey('Users.UserID'), nullable=False)
    MonthlyTarget = db.Column(db.Float, nullable=True)
    CommissionRate = db.Column(db.Float, nullable=True)
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('sales_reps', lazy=True))

    # Relationship with User
    user = db.relationship('User', backref='sales_rep')

class Commission(db.Model):
    __tablename__ = 'Commissions'
    CommissionID = db.Column(db.Integer, primary_key=True)
    RepID = db.Column(db.Integer, db.ForeignKey('SalesReps.RepID'), nullable=False)
    Month = db.Column(db.String(20), nullable=False)
    TotalSales = db.Column(db.Float, nullable=False)
    CommissionEarned = db.Column(db.Float, nullable=False)

    # Relationship with SalesRep
    sales_rep = db.relationship('SalesRep', backref='commissions')

class RepStock(db.Model):
    __tablename__ = 'RepStocks'
    RepStockID = db.Column(db.Integer, primary_key=True)
    SalesRepID = db.Column(db.Integer, db.ForeignKey('SalesReps.RepID'), nullable=False)
    ProductID = db.Column(db.Integer, db.ForeignKey('Products.ProductID'), nullable=False)
    Quantity = db.Column(db.Integer, nullable=False, default=0)
    AssignedCost = db.Column(Float, nullable=True)  # Add this column

    sales_rep = db.relationship('SalesRep', backref='rep_stocks')
    product = db.relationship('Product', backref='rep_stocks')


class ToVisit(db.Model):
    __tablename__ = 'ToVisit'
    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey('Customers.CustomerID'), nullable=False)
    rep_id = Column(Integer, ForeignKey('Users.UserID'), nullable=False)
    visit_date = Column(Date, nullable=False)
    status = Column(String(50), default='Pending')
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    customer = relationship("Customer", backref="to_visit_entries")
    rep = relationship("User", backref="to_visit_entries")

class Expenses(db.Model):
    __tablename__ = 'Expenses'
    ExpenseID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Description = db.Column(db.String(255), nullable=False)
    Amount = db.Column(db.Float, nullable=False)
    Date = db.Column(db.DateTime, default=datetime.utcnow)
    Category = db.Column(db.String(255), nullable=False)
    CreatedBy = db.Column(db.Integer, db.ForeignKey('Users.UserID'), nullable=False)
    OrganizationID = db.Column(db.Integer, db.ForeignKey('Organizations.OrganizationID'), nullable=False)
    organization = db.relationship('Organization', backref=db.backref('expenses', lazy=True))
    user = db.relationship('User', backref='expenses')


class Organization(db.Model):
    __tablename__ = 'Organizations'
    OrganizationID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Name = db.Column(db.String(255), nullable=False, unique=True)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)


