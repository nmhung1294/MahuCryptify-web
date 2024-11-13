import math

#Extend Ext_Euclide
def Ext_Euclide(a, b):
    if b == 0: 
        d = a
        x = 1
        y = 0
        return d,x,y
    x2 = 1
    x1 = 0
    y1 = 1
    y2 = 0
    while (b > 0):
        q = a // b
        r = a  % b
        x = x2 - q*x1
        y = y2 - q*y1
        a = b
        b = r
        x2 = x1
        x1 = x
        y2 = y1
        y1 = y
    d = a
    x = x2
    y = y2
    return d,x,y

#Modular Exponentiation
def modular_exponentiation(b, n, m):
    x = 1
    power = b % m 

    while n > 0:
        if n % 2 == 1:
            x = (x * power) % m
        power = (power * power) % m
        n = n // 2
    return x 

def find_quadratic_residue(p):
    quadratic_residue = {}
    for i in range(1, p//2 + 1):
        m = modular_exponentiation(i,2,p)
        quadratic_residue[str(m)] = (i, p-i)
    return quadratic_residue

def double(point, a, p):
    x, y = point
    if (y == 0):
        return (0,0)
    _lambda = ((3*x**2 + a) * Ext_Euclide(2*y, p)[1]) % p
    x_r = (_lambda**2 - 2*x) % p
    y_r = (_lambda*(x - x_r) - y) % p
    return (x_r, y_r)

def add(point1, point2, a, p):
    x1, y1 = point1
    x2, y2 = point2
    if (point1 == (0,0)):
        return point2
    if (point2 == (0,0)):
        return point1
    if (x1 == x2 and y1 == y2):
        return double(point1, a, p)
    if (x1 == x2 and y1 != y2):
        return (0,0)
    _lambda = ((y2 - y1) * Ext_Euclide(x2 - x1, p)[1]) % p
    x_r = (_lambda**2 - x1 - x2) % p
    y_r = (_lambda*(x1 - x_r) - y1) % p
    return (x_r, y_r)

def double_and_add(point, n, a, p):
    if (n == 0):
        return (0,0)
    if (n == 1):
        return point
    T = point
    d = bin(n)[2:]
    l = len(d)
    for i in range(1, l):
        T = double(T, a, p)
        if (d[i] == '1'):
            T = add(T, point, a, p)
    return T
