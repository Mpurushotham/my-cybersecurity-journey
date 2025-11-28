# Python Prodigy: From Zero to Hero
## The Complete Python Programming Guide with 500+ Practical Examples

**Author:** Purushotham Muktha  
**Built with ❤️ to share knowledge globally**

---

## Table of Contents

1. [Module 1: The Python Foundation](#module-1)
2. [Module 2: Logic and Flow Control](#module-2)
3. [Module 3: Loops and Repetition](#module-3)
4. [Module 4: Data Structures](#module-4)
5. [Module 5: Functions and Modules](#module-5)
6. [Module 6: Object-Oriented Programming](#module-6)
7. [Module 7: Error Handling and File I/O](#module-7)
8. [Module 8: Web Development with Flask](#module-8)

---

# Module 1: The Python Foundation - Your First Code

## Overview
Welcome to Python! This module introduces you to programming fundamentals. You'll write your first program, understand variables, and learn how computers store and process data.

## Why Python?
- Easy to learn and read
- Versatile (web, data science, AI, automation)
- Huge community and library support
- High demand in job market

---

## 1.1 Your First Python Program

### Example 1: Hello World
```python
print("Hello, World!")
```
**Output:** `Hello, World!`

### Example 2: Multiple Print Statements
```python
print("Welcome to Python!")
print("Let's learn programming")
print("This is exciting!")
```

### Example 3: Print with Numbers
```python
print(42)
print(3.14159)
print(True)
```

### Example 4: Print Multiple Items
```python
print("Python", "is", "awesome")
print("I", "am", 25, "years old")
```

### Example 5: Print with Separator
```python
print("apple", "banana", "cherry", sep=", ")
# Output: apple, banana, cherry
```

### Example 6: Print with Custom End
```python
print("Hello", end=" ")
print("World")
# Output: Hello World
```

### Example 7: Empty Print (Blank Line)
```python
print()
print("This creates a blank line above")
```

### Example 8: Print Special Characters
```python
print("Hello\nWorld")  # \n = newline
print("Hello\tWorld")  # \t = tab
```

### Example 9: Print Quotes
```python
print("She said, \"Hello!\"")
print('He said, "Hi!"')
```

### Example 10: Print Raw Strings
```python
print(r"C:\new\folder")  # r prefix for raw string
```

---

## 1.2 Comments in Python

### Example 11: Single Line Comment
```python
# This is a comment
print("This code runs")
```

### Example 12: Inline Comment
```python
print("Hello")  # This prints Hello
```

### Example 13: Multiple Comments
```python
# This is line 1 of comments
# This is line 2 of comments
# This is line 3 of comments
print("Code runs")
```

### Example 14: Multi-line String as Comment
```python
"""
This is a multi-line comment.
It can span multiple lines.
Often used for documentation.
"""
print("Hello")
```

### Example 15: Commenting Out Code
```python
# print("This won't run")
print("This will run")
```

---

## 1.3 Variables - Storing Data

### Example 16: Creating Variables
```python
name = "Alice"
age = 25
height = 5.6
is_student = True
```

### Example 17: Using Variables
```python
message = "Hello"
print(message)
```

### Example 18: Variable Reassignment
```python
x = 10
print(x)  # 10
x = 20
print(x)  # 20
```

### Example 19: Multiple Assignment
```python
a, b, c = 1, 2, 3
print(a, b, c)  # 1 2 3
```

### Example 20: Same Value Multiple Variables
```python
x = y = z = 0
print(x, y, z)  # 0 0 0
```

### Example 21: Swapping Variables
```python
a = 5
b = 10
a, b = b, a
print(a, b)  # 10 5
```

### Example 22: Variable Naming Rules
```python
# Valid names
user_name = "John"
age2 = 25
_private = "hidden"

# Invalid names (will cause errors)
# 2age = 25        # Can't start with number
# user-name = "x"  # No hyphens
# class = "Python" # Reserved keyword
```

### Example 23: Descriptive Variable Names
```python
# Bad
x = 100
y = 50

# Good
total_price = 100
discount_amount = 50
```

### Example 24: Case Sensitivity
```python
Name = "Alice"
name = "Bob"
print(Name)  # Alice
print(name)  # Bob
```

### Example 25: Variable Deletion
```python
x = 10
print(x)  # 10
del x
# print(x)  # Error: x is not defined
```

---

## 1.4 Data Types

### Example 26: Integer Type
```python
age = 25
year = 2024
negative = -10
print(type(age))  # <class 'int'>
```

### Example 27: Float Type
```python
price = 19.99
temperature = -5.5
pi = 3.14159
print(type(price))  # <class 'float'>
```

### Example 28: String Type
```python
name = "Alice"
city = 'New York'
message = """Multiple
line
string"""
print(type(name))  # <class 'str'>
```

### Example 29: Boolean Type
```python
is_active = True
is_logged_in = False
print(type(is_active))  # <class 'bool'>
```

### Example 30: Checking Type
```python
x = 42
print(type(x))  # <class 'int'>
print(isinstance(x, int))  # True
```

### Example 31: Integer Operations
```python
a = 10
b = 3
print(a + b)   # 13 (addition)
print(a - b)   # 7 (subtraction)
print(a * b)   # 30 (multiplication)
print(a / b)   # 3.333... (division)
print(a // b)  # 3 (floor division)
print(a % b)   # 1 (modulus/remainder)
print(a ** b)  # 1000 (exponentiation)
```

### Example 32: Float Precision
```python
x = 0.1 + 0.2
print(x)  # 0.30000000000000004
print(round(x, 2))  # 0.3
```

### Example 33: Large Numbers
```python
billion = 1_000_000_000
print(billion)  # 1000000000
```

### Example 34: String Creation
```python
single = 'Hello'
double = "World"
triple = '''Multi
line'''
```

### Example 35: String Length
```python
text = "Python"
print(len(text))  # 6
```

### Example 36: String Indexing
```python
word = "Python"
print(word[0])   # P
print(word[1])   # y
print(word[-1])  # n (last character)
print(word[-2])  # o (second from last)
```

### Example 37: String Slicing
```python
text = "Python Programming"
print(text[0:6])    # Python
print(text[7:])     # Programming
print(text[:6])     # Python
print(text[::2])    # Pto rgamn (every 2nd char)
print(text[::-1])   # gnimmargorP nohtyP (reverse)
```

### Example 38: String Concatenation
```python
first = "Hello"
last = "World"
full = first + " " + last
print(full)  # Hello World
```

### Example 39: String Repetition
```python
laugh = "ha" * 3
print(laugh)  # hahaha
```

### Example 40: String Methods - Case
```python
text = "Python Programming"
print(text.upper())      # PYTHON PROGRAMMING
print(text.lower())      # python programming
print(text.title())      # Python Programming
print(text.capitalize()) # Python programming
print(text.swapcase())   # pYTHON pROGRAMMING
```

### Example 41: String Methods - Search
```python
text = "Python is awesome"
print(text.find("is"))      # 7
print(text.index("is"))     # 7
print(text.count("o"))      # 2
print(text.startswith("Py"))# True
print(text.endswith("me"))  # True
```

### Example 42: String Methods - Modify
```python
text = "  Python  "
print(text.strip())      # "Python"
print(text.lstrip())     # "Python  "
print(text.rstrip())     # "  Python"
print(text.replace("Python", "Java"))  # "  Java  "
```

### Example 43: String Methods - Split/Join
```python
text = "apple,banana,cherry"
fruits = text.split(",")
print(fruits)  # ['apple', 'banana', 'cherry']

joined = " | ".join(fruits)
print(joined)  # apple | banana | cherry
```

### Example 44: String Checking Methods
```python
print("123".isdigit())     # True
print("abc".isalpha())     # True
print("abc123".isalnum())  # True
print("   ".isspace())     # True
print("Hello".islower())   # False
print("HELLO".isupper())   # True
```

### Example 45: Boolean Operations
```python
a = True
b = False
print(a and b)  # False
print(a or b)   # True
print(not a)    # False
```

### Example 46: Boolean from Comparisons
```python
x = 5
y = 10
print(x < y)   # True
print(x == y)  # False
print(x != y)  # True
```

### Example 47: Truthy and Falsy Values
```python
print(bool(0))      # False
print(bool(1))      # True
print(bool(""))     # False
print(bool("text")) # True
print(bool([]))     # False (empty list)
print(bool([1]))    # True (non-empty list)
```

### Example 48: None Type
```python
x = None
print(x)         # None
print(type(x))   # <class 'NoneType'>
print(x is None) # True
```

### Example 49: Type Conversion to Int
```python
x = int(3.9)        # 3
y = int("100")      # 100
z = int("1010", 2)  # 10 (binary to int)
print(x, y, z)
```

### Example 50: Type Conversion to Float
```python
x = float(5)      # 5.0
y = float("3.14") # 3.14
print(x, y)
```

### Example 51: Type Conversion to String
```python
x = str(100)   # "100"
y = str(3.14)  # "3.14"
z = str(True)  # "True"
print(x, y, z)
```

### Example 52: Type Conversion to Bool
```python
print(bool(1))       # True
print(bool(0))       # False
print(bool("False")) # True (non-empty string)
```

### Example 53: Complex Type Conversion
```python
# String to int to float
text = "42"
num = int(text)
decimal = float(num)
print(text, num, decimal)  # "42" 42 42.0
```

---

## 1.5 User Input

### Example 54: Basic Input
```python
name = input("What's your name? ")
print("Hello, " + name)
```

### Example 55: Input with Numbers
```python
age = input("Enter your age: ")
print("You are " + age + " years old")
```

### Example 56: Converting Input to Int
```python
age = int(input("Enter your age: "))
next_year = age + 1
print("Next year you'll be", next_year)
```

### Example 57: Converting Input to Float
```python
price = float(input("Enter price: "))
tax = price * 0.1
total = price + tax
print("Total with tax:", total)
```

### Example 58: Multiple Inputs
```python
name = input("Name: ")
age = input("Age: ")
city = input("City: ")
print(f"{name} is {age} years old and lives in {city}")
```

### Example 59: Input Validation (Basic)
```python
age = input("Enter age: ")
if age.isdigit():
    print("Valid age:", age)
else:
    print("Please answer yes or no")
```

### Example 130: Ternary Operator (Conditional Expression)
```python
age = 20
status = "Adult" if age >= 18 else "Minor"
print(status)  # Adult

# Traditional if-else equivalent:
if age >= 18:
    status = "Adult"
else:
    status = "Minor"
```

### Example 131: Checking Empty String
```python
name = input("Enter your name: ")

if name:  # True if name is not empty
    print(f"Hello, {name}!")
else:
    print("You didn't enter a name")
```

### Example 132: Checking Number Range
```python
score = 85

if 0 <= score <= 100:
    print("Valid score")
else:
    print("Invalid score")
```

### Example 133: Membership Test
```python
favorite_color = "blue"

if favorite_color in ["red", "blue", "green"]:
    print("Primary color!")
else:
    print("Not a primary color")
```

### Example 134: Identity Test
```python
x = None

if x is None:
    print("x has no value")
else:
    print(f"x has value: {x}")
```

### Example 135: Checking Even/Odd
```python
number = int(input("Enter a number: "))

if number % 2 == 0:
    print(f"{number} is even")
else:
    print(f"{number} is odd")
```

### Example 136: BMI Calculator with Conditions
```python
weight = float(input("Enter weight in kg: "))
height = float(input("Enter height in meters: "))

bmi = weight / (height ** 2)

if bmi < 18.5:
    category = "Underweight"
elif bmi < 25:
    category = "Normal weight"
elif bmi < 30:
    category = "Overweight"
else:
    category = "Obese"

print(f"BMI: {bmi:.1f} - {category}")
```

### Example 137: Leap Year Checker
```python
year = int(input("Enter a year: "))

if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
    print(f"{year} is a leap year")
else:
    print(f"{year} is not a leap year")
```

### Example 138: Temperature Converter
```python
temp = float(input("Enter temperature: "))
unit = input("Is this (C)elsius or (F)ahrenheit? ").upper()

if unit == "C":
    converted = (temp * 9/5) + 32
    print(f"{temp}°C = {converted:.1f}°F")
elif unit == "F":
    converted = (temp - 32) * 5/9
    print(f"{temp}°F = {converted:.1f}°C")
else:
    print("Invalid unit!")
```

### Example 139: Login System
```python
CORRECT_USERNAME = "admin"
CORRECT_PASSWORD = "pass123"

username = input("Username: ")
password = input("Password: ")

if username == CORRECT_USERNAME and password == CORRECT_PASSWORD:
    print("✓ Login successful!")
elif username == CORRECT_USERNAME:
    print("✗ Incorrect password")
else:
    print("✗ User not found")
```

### Example 140: Discount Calculator
```python
price = float(input("Enter price: $"))
is_member = input("Are you a member? (yes/no): ").lower() == "yes"

if is_member:
    if price > 100:
        discount = 0.20  # 20% for members spending over $100
    else:
        discount = 0.10  # 10% for members
else:
    if price > 100:
        discount = 0.05  # 5% for non-members spending over $100
    else:
        discount = 0  # No discount

final_price = price * (1 - discount)
print(f"Final price: ${final_price:.2f} ({discount*100:.0f}% discount)")
```

---

## 2.4 Practical Lab: Grading System

### Example 141: Simple Grading System
```python
score = int(input("Enter your score (0-100): "))

if score >= 90:
    grade = "A"
elif score >= 80:
    grade = "B"
elif score >= 70:
    grade = "C"
elif score >= 60:
    grade = "D"
else:
    grade = "F"

print(f"Your grade is: {grade}")
```

### Example 142: Enhanced Grading System
```python
score = int(input("Enter your score (0-100): "))

# Validate input
if score < 0 or score > 100:
    print("Invalid score! Must be between 0 and 100.")
else:
    if score >= 90:
        grade = "A"
        message = "Excellent!"
    elif score >= 80:
        grade = "B"
        message = "Good job!"
    elif score >= 70:
        grade = "C"
        message = "Satisfactory"
    elif score >= 60:
        grade = "D"
        message = "Needs improvement"
    else:
        grade = "F"
        message = "Failed"
    
    print(f"Score: {score}")
    print(f"Grade: {grade}")
    print(f"Comment: {message}")
```

### Example 143: Plus/Minus Grading
```python
score = int(input("Enter your score (0-100): "))

if score >= 97:
    grade = "A+"
elif score >= 93:
    grade = "A"
elif score >= 90:
    grade = "A-"
elif score >= 87:
    grade = "B+"
elif score >= 83:
    grade = "B"
elif score >= 80:
    grade = "B-"
elif score >= 77:
    grade = "C+"
elif score >= 73:
    grade = "C"
elif score >= 70:
    grade = "C-"
elif score >= 60:
    grade = "D"
else:
    grade = "F"

print(f"Grade: {grade}")
```

---

## 2.5 Mini-Project: Number Guessing Game

### Example 144: Basic Guessing Game
```python
secret_number = 7

guess = int(input("Guess a number between 1-10: "))

if guess == secret_number:
    print("🎉 Correct! You won!")
elif guess > secret_number:
    print("📉 Too high!")
else:
    print("📈 Too low!")

print(f"The number was {secret_number}")
```

### Example 145: Enhanced Guessing Game
```python
import random

secret_number = random.randint(1, 10)
guess = int(input("I'm thinking of a number between 1-10. Guess it: "))

if guess == secret_number:
    print("🎉 Amazing! You got it on the first try!")
elif guess > secret_number:
    print(f"📉 Too high! The number was {secret_number}")
    difference = guess - secret_number
    if difference <= 2:
        print("But you were close!")
else:
    print(f"📈 Too low! The number was {secret_number}")
    difference = secret_number - guess
    if difference <= 2:
        print("But you were close!")
```

### Example 146: Multiple Hints Game
```python
secret_number = 7
guess = int(input("Guess the number (1-10): "))

if guess == secret_number:
    print("🎉 Perfect! You win!")
else:
    # Give distance hint
    distance = abs(guess - secret_number)
    
    if distance == 1:
        print("🔥 Very hot! Off by just 1!")
    elif distance == 2:
        print("♨️ Hot! Off by 2")
    elif distance <= 3:
        print("🌡️ Warm! Off by 3")
    else:
        print("❄️ Cold! Way off")
    
    # Give high/low hint
    if guess > secret_number:
        print("📉 Your guess is too high")
    else:
        print("📈 Your guess is too low")
    
    print(f"\nThe number was {secret_number}")
```

### Example 147: Game with Difficulty Levels
```python
import random

print("Choose difficulty:")
print("1. Easy (1-10)")
print("2. Medium (1-50)")
print("3. Hard (1-100)")

difficulty = int(input("Enter choice (1-3): "))

if difficulty == 1:
    max_num = 10
    attempts = 3
elif difficulty == 2:
    max_num = 50
    attempts = 5
elif difficulty == 3:
    max_num = 100
    attempts = 7
else:
    print("Invalid choice! Defaulting to Easy.")
    max_num = 10
    attempts = 3

secret_number = random.randint(1, max_num)
print(f"\nGuess the number between 1-{max_num}")
print(f"You have {attempts} attempts")

guess = int(input("Your guess: "))

if guess == secret_number:
    print("🎉 Correct! You won!")
elif guess > secret_number:
    print(f"Too high! The number was {secret_number}")
else:
    print(f"Too low! The number was {secret_number}")
```

### Example 148: Age Classifier
```python
age = int(input("Enter your age: "))

if age < 0:
    print("Invalid age!")
elif age < 2:
    print("You're a baby")
elif age < 4:
    print("You're a toddler")
elif age < 13:
    print("You're a child")
elif age < 20:
    print("You're a teenager")
elif age < 65:
    print("You're an adult")
else:
    print("You're a senior citizen")
```

### Example 149: Triangle Validator
```python
side1 = float(input("Enter first side: "))
side2 = float(input("Enter second side: "))
side3 = float(input("Enter third side: "))

# Check if it forms a valid triangle
if side1 + side2 > side3 and side2 + side3 > side1 and side1 + side3 > side2:
    print("✓ This forms a valid triangle")
    
    # Check triangle type
    if side1 == side2 == side3:
        print("Type: Equilateral (all sides equal)")
    elif side1 == side2 or side2 == side3 or side1 == side3:
        print("Type: Isosceles (two sides equal)")
    else:
        print("Type: Scalene (all sides different)")
else:
    print("✗ This does not form a valid triangle")
```

### Example 150: Palindrome Checker
```python
word = input("Enter a word: ").lower()
reversed_word = word[::-1]

if word == reversed_word:
    print(f"'{word}' is a palindrome!")
else:
    print(f"'{word}' is not a palindrome")
```

---

## Common Pitfalls & Best Practices

### Example 151: Pitfall - Missing Colon
```python
# Wrong:
# if x > 10
#     print("Greater")

# Correct:
x = 15
if x > 10:
    print("Greater")
```

### Example 152: Pitfall - Wrong Indentation
```python
# Wrong:
# if x > 10:
# print("Greater")  # IndentationError

# Correct:
x = 15
if x > 10:
    print("Greater")
```

### Example 153: Pitfall - Assignment vs Comparison
```python
x = 10

# Wrong (assignment, not comparison):
# if x = 10:  # SyntaxError
#     print("Ten")

# Correct:
if x == 10:
    print("Ten")
```

### Example 154: Pitfall - Multiple Conditions
```python
x = 5

# Wrong:
# if x == 3 or 5:  # This doesn't work as expected
#     print("Found")

# Correct:
if x == 3 or x == 5:
    print("Found")

# Or better:
if x in [3, 5]:
    print("Found")
```

### Example 155: Best Practice - Use elif
```python
score = 85

# Less efficient:
if score >= 90:
    grade = "A"
if score >= 80 and score < 90:
    grade = "B"
if score >= 70 and score < 80:
    grade = "C"

# Better (using elif):
if score >= 90:
    grade = "A"
elif score >= 80:
    grade = "B"
elif score >= 70:
    grade = "C"
```

### Example 156: Best Practice - Avoid Deep Nesting
```python
# Bad (deeply nested):
if condition1:
    if condition2:
        if condition3:
            if condition4:
                print("All conditions met")

# Better (use logical operators):
if condition1 and condition2 and condition3 and condition4:
    print("All conditions met")
```

### Example 157: Best Practice - Early Return Pattern
```python
def check_age(age):
    # Handle invalid cases first
    if age < 0:
        return "Invalid age"
    if age < 18:
        return "Minor"
    if age < 65:
        return "Adult"
    return "Senior"

print(check_age(25))
```

### Example 158: Best Practice - Readable Conditions
```python
age = 25
has_license = True
has_insurance = True

# Less readable:
if age >= 18 and has_license and has_insurance:
    can_drive = True

# More readable:
is_adult = age >= 18
is_legally_qualified = has_license and has_insurance
can_drive = is_adult and is_legally_qualified
```

### Example 159: Best Practice - Truthy/Falsy
```python
name = input("Enter name: ")

# Verbose:
if len(name) > 0:
    print(f"Hello, {name}")

# Better (more Pythonic):
if name:
    print(f"Hello, {name}")
```

### Example 160: Review Exercise - Complete Calculator
```python
print("Simple Calculator")
print("1. Addition")
print("2. Subtraction")
print("3. Multiplication")
print("4. Division")

choice = input("\nChoose operation (1-4): ")

if choice in ['1', '2', '3', '4']:
    num1 = float(input("Enter first number: "))
    num2 = float(input("Enter second number: "))
    
    if choice == '1':
        result = num1 + num2
        operation = "+"
    elif choice == '2':
        result = num1 - num2
        operation = "-"
    elif choice == '3':
        result = num1 * num2
        operation = "*"
    elif choice == '4':
        if num2 != 0:
            result = num1 / num2
            operation = "/"
        else:
            print("Error: Cannot divide by zero!")
            exit()
    
    print(f"{num1} {operation} {num2} = {result}")
else:
    print("Invalid choice!")
```

---

# Module 3: Loops and Repetition - Working Smarter, Not Harder

## Overview
Automate repetitive tasks with loops! Learn to use for loops and while loops to make your code more efficient and powerful.

---

## 3.1 For Loops with range()

### Example 161: Basic For Loop
```python
for i in range(5):
    print(i)
# Output: 0 1 2 3 4
```

### Example 162: Range with Start and Stop
```python
for i in range(1, 6):
    print(i)
# Output: 1 2 3 4 5
```

### Example 163: Range with Step
```python
for i in range(0, 10, 2):
    print(i)
# Output: 0 2 4 6 8
```

### Example 164: Counting Backwards
```python
for i in range(10, 0, -1):
    print(i)
print("Blastoff!")
```

### Example 165: Loop with String
```python
for i in range(3):
    print(f"Iteration {i}")
```

### Example 166: Nested For Loops
```python
for i in range(3):
    for j in range(3):
        print(f"i={i}, j={j}")
```

### Example 167: Multiplication Table
```python
number = 5
for i in range(1, 11):
    print(f"{number} x {i} = {number * i}")
```

### Example 168: Sum of Numbers
```python
total = 0
for i in range(1, 101):
    total += i
print(f"Sum of 1 to 100: {total}")
```

### Example 169: Even Numbers
```python
print("Even numbers from 1 to 20:")
for i in range(2, 21, 2):
    print(i, end=" ")
```

### Example 170: Factorial Calculator
```python
n = 5
factorial = 1
for i in range(1, n + 1):
    factorial *= i
print(f"Factorial of {n} is {factorial}")
```

### Example 171: Power Table
```python
base = 2
for exponent in range(11):
    print(f"{base}^{exponent} = {base ** exponent}")
```

### Example 172: Pattern Printing - Stars
```python
for i in range(5):
    print("*" * (i + 1))
# Output:
# *
# **
# ***
# ****
# *****
```

### Example 173: Pattern - Numbers
```python
for i in range(1, 6):
    for j in range(1, i + 1):
        print(j, end=" ")
    print()
```

### Example 174: Pattern - Pyramid
```python
n = 5
for i in range(1, n + 1):
    print(" " * (n - i) + "*" * (2 * i - 1))
```

### Example 175: FizzBuzz Game
```python
for i in range(1, 21):
    if i % 3 == 0 and i % 5 == 0:
        print("FizzBuzz")
    elif i % 3 == 0:
        print("Fizz")
    elif i % 5 == 0:
        print("Buzz")
    else:
        print(i)
```

---

## 3.2 Iterating Over Strings

### Example 176: Loop Through String
```python
word = "Python"
for letter in word:
    print(letter)
```

### Example 177: Counting Vowels
```python
text = "Hello World"
vowels = "aeiouAEIOU"
count = 0

for char in text:
    if char in vowels:
        count += 1

print(f"Number of vowels: {count}")
```

### Example 178: String with Index
```python
word = "Python"
for index, letter in enumerate(word):
    print(f"Index {index}: {letter}")
```

### Example 179: Reverse String
```python
text = "Hello"
reversed_text = ""

for char in text:
    reversed_text = char + reversed_text

print(reversed_text)  # olleH
```

### Example 180: Character Classification
```python
text = "Python123"
letters = 0
digits = 0

for char in text:
    if char.isalpha():
        letters += 1
    elif char.isdigit():
        digits += 1

print(f"Letters: {letters}, Digits: {digits}")
```

---

## 3.3 While Loops

### Example 181: Basic While Loop
```python
count = 0
while count < 5:
    print(count)
    count += 1
```

### Example 182: While with Condition
```python
number = 1
while number <= 10:
    print(number)
    number += 1
```

### Example 183: User Input Loop
```python
password = ""
while password != "secret":
    password = input("Enter password: ")
print("Access granted!")
```

### Example 184: Sum Until Zero
```python
total = 0
number = int(input("Enter number (0 to stop): "))

while number != 0:
    total += number
    number = int(input("Enter number (0 to stop): "))

print(f"Total sum: {total}")
```

### Example 185: Countdown Timer
```python
import time

countdown = 5
while countdown > 0:
    print(countdown)
    time.sleep(1)  # Wait 1 second
    countdown -= 1
print("Time's up!")
```

### Example 186: Doubling Numbers
```python
number = 1
while number < 1000:
    print(number)
    number *= 2
```

### Example 187: Menu Loop
```python
choice = ""
while choice != "quit":
    print("\n1. Option A")
    print("2. Option B")
    print("Type 'quit' to exit")
    choice = input("Choice: ")
    
    if choice == "1":
        print("You chose A")
    elif choice == "2":
        print("You chose B")
```

### Example 188: Validation Loop
```python
age = -1
while age < 0 or age > 120:
    age = int(input("Enter your age (0-120): "))
    if age < 0 or age > 120:
        print("Invalid age!")
print(f"Your age is {age}")
```

### Example 189: Guess Until Correct
```python
secret = 7
guess = -1

while guess != secret:
    guess = int(input("Guess the number: "))
    if guess < secret:
        print("Too low!")
    elif guess > secret:
        print("Too high!")

print("Correct!")
```

### Example 190: Infinite Loop with Break
```python
while True:
    user_input = input("Enter 'exit' to quit: ")
    if user_input == "exit":
        break
    print(f"You entered: {user_input}")
```

---

## 3.4 Break and Continue

### Example 191: Break Statement
```python
for i in range(10):
    if i == 5:
        break
    print(i)
# Output: 0 1 2 3 4
```

### Example 192: Break in While Loop
```python
count = 0
while count < 100:
    print(count)
    count += 1
    if count == 5:
        break
```

### Example 193: Continue Statement
```python
for i in range(10):
    if i % 2 == 0:
        continue  # Skip even numbers
    print(i)
# Output: 1 3 5 7 9
```

### Example 194: Continue in While Loop
```python
count = 0
while count < 10:
    count += 1
    if count % 2 == 0:
        continue
    print(count)
```

### Example 195: Break with Condition
```python
for i in range(1, 101):
    if i ** 2 > 500:
        print(f"Stopping at {i}")
        break
    print(f"{i} squared is {i**2}")
```

### Example 196: Multiple Break Conditions
```python
for i in range(100):
    if i > 50:
        print("Reached 50")
        break
    if i % 10 == 0:
        print(f"Multiple of 10: {i}")
```

### Example 197: Continue to Skip Values
```python
for i in range(1, 21):
    if i % 3 == 0:
        continue  # Skip multiples of 3
    print(i)
```

### Example 198: Search with Break
```python
numbers = [5, 12, 7, 23, 9, 15]
target = 23

for num in numbers:
    if num == target:
        print(f"Found {target}!")
        break
else:
    print(f"{target} not found")
```

### Example 199: Password Attempts
```python
MAX_ATTEMPTS = 3
attempts = 0
correct_password = "secret123"

while attempts < MAX_ATTEMPTS:
    password = input("Enter password: ")
    attempts += 1
    
    if password == correct_password:
        print("Access granted!")
        break
    else:
        remaining = MAX_ATTEMPTS - attempts
        if remaining > 0:
            print(f"Wrong! {remaining} attempts left")
else:
    print("Account locked!")
```

### Example 200: Prime Number Checker
```python
number = int(input("Enter a number: "))

if number < 2:
    print("Not prime")
else:
    is_prime = True
    for i in range(2, int(number ** 0.5) + 1):
        if number % i == 0:
            is_prime = False
            break
    
    if is_prime:
        print(f"{number} is prime")
    else:
        print(f"{number} is not prime")
    print("Invalid age!")
```

### Example 60: Input with Default Prompt
```python
answer = input("Continue? (yes/no): ")
print("You answered:", answer)
```

---

## 1.6 String Formatting

### Example 61: String Concatenation
```python
name = "Alice"
age = 25
message = "My name is " + name + " and I am " + str(age)
print(message)
```

### Example 62: format() Method
```python
name = "Bob"
age = 30
message = "My name is {} and I am {}".format(name, age)
print(message)
```

### Example 63: format() with Index
```python
message = "{0} is {1} years old. {0} likes Python.".format("Alice", 25)
print(message)
```

### Example 64: format() with Names
```python
message = "{name} is {age} years old".format(name="Charlie", age=35)
print(message)
```

### Example 65: f-strings (Modern)
```python
name = "David"
age = 40
message = f"My name is {name} and I am {age}"
print(message)
```

### Example 66: f-strings with Expressions
```python
a = 10
b = 20
print(f"The sum of {a} and {b} is {a + b}")
```

### Example 67: f-strings with Formatting
```python
pi = 3.14159265359
print(f"Pi is approximately {pi:.2f}")  # 3.14
```

### Example 68: f-strings with Alignment
```python
name = "Alice"
print(f"{name:>10}")  # Right align in 10 spaces
print(f"{name:<10}")  # Left align
print(f"{name:^10}")  # Center align
```

### Example 69: % Formatting (Old Style)
```python
name = "Eve"
age = 28
print("Name: %s, Age: %d" % (name, age))
```

### Example 70: Multi-line Strings
```python
text = """
Hello,
This is a multi-line
string in Python!
"""
print(text)
```

---

## 1.7 Basic Math Operations

### Example 71: Addition
```python
x = 15
y = 10
result = x + y
print(result)  # 25
```

### Example 72: Subtraction
```python
x = 20
y = 8
result = x - y
print(result)  # 12
```

### Example 73: Multiplication
```python
x = 6
y = 7
result = x * y
print(result)  # 42
```

### Example 74: Division
```python
x = 20
y = 3
result = x / y
print(result)  # 6.666666666666667
```

### Example 75: Floor Division
```python
x = 20
y = 3
result = x // y
print(result)  # 6
```

### Example 76: Modulus (Remainder)
```python
x = 20
y = 3
result = x % y
print(result)  # 2
```

### Example 77: Exponentiation
```python
x = 2
y = 8
result = x ** y
print(result)  # 256
```

### Example 78: Operator Precedence
```python
result = 2 + 3 * 4
print(result)  # 14 (not 20)

result = (2 + 3) * 4
print(result)  # 20
```

### Example 79: Compound Assignment
```python
x = 10
x += 5   # x = x + 5
print(x) # 15
x -= 3   # x = x - 3
print(x) # 12
x *= 2   # x = x * 2
print(x) # 24
x /= 4   # x = x / 4
print(x) # 6.0
```

### Example 80: Absolute Value
```python
x = -15
result = abs(x)
print(result)  # 15
```

### Example 81: Rounding
```python
x = 3.7
print(round(x))      # 4
print(round(3.14159, 2))  # 3.14
```

### Example 82: Min and Max
```python
print(min(5, 10, 3, 8))  # 3
print(max(5, 10, 3, 8))  # 10
```

### Example 83: Power Function
```python
result = pow(2, 3)   # 2^3
print(result)  # 8

result = pow(2, 3, 5)  # (2^3) % 5
print(result)  # 3
```

### Example 84: Sum Function
```python
numbers = [1, 2, 3, 4, 5]
total = sum(numbers)
print(total)  # 15
```

### Example 85: Division by Zero Awareness
```python
# This will cause an error:
# result = 10 / 0  # ZeroDivisionError

# Safe approach (we'll learn error handling later)
divisor = 0
if divisor != 0:
    result = 10 / divisor
else:
    print("Cannot divide by zero!")
```

---

## 1.8 Practical Lab: Personal Greeting Program

### Example 86: Lab Solution
```python
# Get user information
name = input("What's your name? ")
age = input("How old are you? ")

# Convert age to integer
age_num = int(age)

# Calculate future age
future_age = age_num + 5

# Print personalized greeting
print(f"Hello, {name}!")
print(f"You are {age_num} years old.")
print(f"In 5 years, you'll be {future_age} years old!")
```

### Example 87: Enhanced Greeting
```python
name = input("Name: ")
age = int(input("Age: "))
city = input("City: ")

print(f"\n{'='*40}")
print(f"Welcome, {name}!")
print(f"Age: {age} years old")
print(f"City: {city}")
print(f"In 10 years: {age + 10} years old")
print(f"{'='*40}")
```

### Example 88: Greeting with Calculation
```python
name = input("Your name: ")
birth_year = int(input("Birth year: "))
current_year = 2024

age = current_year - birth_year
print(f"Hello {name}! You are approximately {age} years old.")
```

---

## 1.9 Mini-Project: Mad Libs Story Generator

### Example 89: Simple Mad Libs
```python
# Get words from user
noun = input("Enter a noun: ")
verb = input("Enter a verb: ")
adjective = input("Enter an adjective: ")

# Create story
story = f"Once upon a time, there was a {adjective} {noun}. "
story += f"It loved to {verb} every day!"

print("\nYour Story:")
print(story)
```

### Example 90: Extended Mad Libs
```python
print("Let's create a funny story!\n")

# Collect words
noun1 = input("Noun: ")
noun2 = input("Another noun: ")
verb = input("Verb (ending in -ing): ")
adjective1 = input("Adjective: ")
adjective2 = input("Another adjective: ")
adverb = input("Adverb: ")
place = input("Place: ")

# Build story
story = f"""
The Tale of the {adjective1} {noun1}

Once upon a time in {place}, there was a {adjective1} {noun1}.
This {noun1} loved {verb} {adverb}. One day, while {verb},
it met a {adjective2} {noun2}. They became best friends and
lived {adverb} ever after!
"""

print(story)
```

### Example 91: Mad Libs with List
```python
# Collect multiple words
words = []
words.append(input("Animal: "))
words.append(input("Color: "))
words.append(input("Food: "))
words.append(input("Place: "))

# Unpack for clarity
animal, color, food, place = words

story = f"I saw a {color} {animal} eating {food} in {place}!"
print("\n" + story)
```

---

## Common Pitfalls & Best Practices

### Example 92: Pitfall - Forgetting Quotes
```python
# Wrong:
# print(Hello)  # NameError

# Correct:
print("Hello")
```

### Example 93: Pitfall - String vs Number
```python
# Wrong approach:
age = input("Age: ")  # This is a STRING
# next_year = age + 1  # TypeError

# Correct approach:
age = int(input("Age: "))
next_year = age + 1
print(next_year)
```

### Example 94: Pitfall - Concatenation Confusion
```python
# Wrong:
age = 25
# message = "I am " + age  # TypeError

# Correct options:
message = "I am " + str(age)
# Or better:
message = f"I am {age}"
print(message)
```

### Example 95: Best Practice - Descriptive Names
```python
# Bad:
x = "John"
y = 25

# Good:
user_name = "John"
user_age = 25
```

### Example 96: Best Practice - Constants
```python
# Use UPPERCASE for constants
PI = 3.14159
MAX_SIZE = 100
DEFAULT_COLOR = "blue"
```

### Example 97: Best Practice - Comments
```python
# Calculate tax
price = 100
TAX_RATE = 0.1  # 10% tax
total = price * (1 + TAX_RATE)
```

### Example 98: Best Practice - Spacing
```python
# Bad:
x=10+20*30

# Good:
x = 10 + 20 * 30
```

### Example 99: Best Practice - Line Length
```python
# Keep lines under 79-100 characters
very_long_variable_name = "If your line is too long, " \
                          "break it across multiple lines"
```

### Example 100: Review Exercise
```python
# Complete personal info program
print("=== Personal Information Form ===\n")

first_name = input("First name: ")
last_name = input("Last name: ")
age = int(input("Age: "))
city = input("City: ")
favorite_color = input("Favorite color: ")

# Create formatted output
print("\n" + "="*40)
print(f"Name: {first_name} {last_name}")
print(f"Age: {age} years old")
print(f"Location: {city}")
print(f"Favorite Color: {favorite_color}")
print(f"Birth Year (approx): {2024 - age}")
print("="*40)
```

---

# Module 2: Gaining Control - Logic and Flow

## Overview
Learn to make your programs intelligent! This module teaches you how to make decisions in code using conditional statements, comparison operators, and logical operators.

---

## 2.1 Comparison Operators

### Example 101: Equal To (==)
```python
x = 5
y = 5
print(x == y)  # True

a = 10
b = 20
print(a == b)  # False
```

### Example 102: Not Equal To (!=)
```python
x = 5
y = 10
print(x != y)  # True

a = "hello"
b = "hello"
print(a != b)  # False
```

### Example 103: Greater Than (>)
```python
score = 85
passing = 60
print(score > passing)  # True

age = 15
adult_age = 18
print(age > adult_age)  # False
```

### Example 104: Less Than (<)
```python
price = 50
budget = 100
print(price < budget)  # True
```

### Example 105: Greater Than or Equal (>=)
```python
score = 90
threshold = 90
print(score >= threshold)  # True

score2 = 85
print(score2 >= threshold)  # False
```

### Example 106: Less Than or Equal (<=)
```python
age = 18
max_age = 18
print(age <= max_age)  # True
```

### Example 107: Comparing Strings
```python
name1 = "Alice"
name2 = "alice"
print(name1 == name2)  # False (case-sensitive)

name3 = "Alice"
print(name1 == name3)  # True
```

### Example 108: Comparing String Length
```python
word1 = "Python"
word2 = "Java"
print(len(word1) > len(word2))  # True (6 > 4)
```

### Example 109: Alphabetical Comparison
```python
print("apple" < "banana")  # True
print("zebra" > "ant")     # True
```

### Example 110: Multiple Comparisons
```python
x = 10
print(0 < x < 20)    # True (x is between 0 and 20)
print(5 <= x <= 15)  # True
```

---

## 2.2 Logical Operators

### Example 111: AND Operator
```python
age = 25
has_license = True

can_drive = age >= 18 and has_license
print(can_drive)  # True
```

### Example 112: AND with False
```python
is_weekend = True
is_raining = True

go_outside = is_weekend and not is_raining
print(go_outside)  # False
```

### Example 113: OR Operator
```python
is_holiday = False
is_weekend = True

is_off_day = is_holiday or is_weekend
print(is_off_day)  # True
```

### Example 114: OR with All False
```python
has_cash = False
has_card = False

can_pay = has_cash or has_card
print(can_pay)  # False
```

### Example 115: NOT Operator
```python
is_raining = False
print(not is_raining)  # True

is_sunny = True
print(not is_sunny)  # False
```

### Example 116: Combining AND and OR
```python
age = 25
is_student = True
has_id = True

gets_discount = (age < 18 or is_student) and has_id
print(gets_discount)  # True
```

### Example 117: Complex Logic
```python
temperature = 75
is_sunny = True
is_weekend = True

perfect_day = (temperature > 70 and temperature < 85) and is_sunny and is_weekend
print(perfect_day)  # True
```

### Example 118: Short-Circuit Evaluation
```python
x = 5
# The second part won't execute because first is False
result = (x > 10) and (x / 0 > 1)  # No error!
print(result)  # False
```

### Example 119: DeMorgan's Laws
```python
a = True
b = False

# not (a and b) == (not a) or (not b)
print(not (a and b))           # True
print((not a) or (not b))      # True

# not (a or b) == (not a) and (not b)
print(not (a or b))            # False
print((not a) and (not b))     # False
```

### Example 120: Truth Tables
```python
# AND truth table
print(True and True)    # True
print(True and False)   # False
print(False and True)   # False
print(False and False)  # False

# OR truth table
print(True or True)     # True
print(True or False)    # True
print(False or True)    # True
print(False or False)   # False
```

---

## 2.3 If Statements

### Example 121: Basic If
```python
age = 20

if age >= 18:
    print("You are an adult")
```

### Example 122: If with Expression
```python
temperature = 85

if temperature > 80:
    print("It's hot outside!")
    print("Stay hydrated")
```

### Example 123: If-Else
```python
age = 15

if age >= 18:
    print("You can vote")
else:
    print("You cannot vote yet")
```

### Example 124: If-Elif-Else
```python
score = 85

if score >= 90:
    print("Grade: A")
elif score >= 80:
    print("Grade: B")
elif score >= 70:
    print("Grade: C")
elif score >= 60:
    print("Grade: D")
else:
    print("Grade: F")
```

### Example 125: Multiple Elif
```python
day = "Monday"

if day == "Monday":
    print("Start of work week")
elif day == "Wednesday":
    print("Middle of week")
elif day == "Friday":
    print("TGIF!")
elif day == "Saturday" or day == "Sunday":
    print("Weekend!")
else:
    print("Regular day")
```

### Example 126: Nested If
```python
age = 25
has_ticket = True

if age >= 18:
    if has_ticket:
        print("You can enter the concert")
    else:
        print("You need a ticket")
else:
    print("You must be 18 or older")
```

### Example 127: Nested If-Else
```python
number = 15

if number > 0:
    if number % 2 == 0:
        print("Positive even number")
    else:
        print("Positive odd number")
else:
    if number % 2 == 0:
        print("Negative even number")
    else:
        print("Negative odd number")
```

### Example 128: If with Multiple Conditions
```python
username = "admin"
password = "secret123"

if username == "admin" and password == "secret123":
    print("Access granted")
else:
    print("Access denied")
```

### Example 129: If with Input
```python
answer = input("Do you like Python? (yes/no): ")

if answer.lower() == "yes":
    print("Great! Keep learning!")
elif answer.lower() == "no":
    print("Give it more time!")
else: