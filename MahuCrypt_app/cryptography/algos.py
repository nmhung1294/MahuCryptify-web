import math
import random
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

def miller_rabin_test(n, k):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = modular_exponentiation(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                break
        else:
            return False    
    return True

def sieve_of_eratosthenes(limit):
    """ Trả về danh sách các số nguyên tố đến giới hạn cho trước. """
    is_prime = [True] * (limit + 1)
    p = 2
    while (p * p <= limit):
        if (is_prime[p] == True):
            for i in range(p * p, limit + 1, p):
                is_prime[i] = False
        p += 1
    return [p for p in range(2, limit + 1) if is_prime[p]]

def largest_prime_factor(n):
    largest_prime = 0
    limit = int(n**0.5) + 1

    # Tạo danh sách các số nguyên tố
    primes = sieve_of_eratosthenes(limit)

    # Kiểm tra từng số nguyên tố
    for p in primes:
        while n % p == 0:
            largest_prime = p
            n //= p

    # Nếu n còn lại lớn hơn 1, thì nó là một số nguyên tố
    if n > 1:
        largest_prime = n
    return largest_prime


def is_quadratic_residue(p, x):
        return pow(x, (p - 1) // 2, p) == 1

def find_point_on_curve(p, a, b):
    #chỉ cần tìm 1 điểm
    for x in range(p):
        y_square = (x**3 + a*x + b) % p
        if is_quadratic_residue(p, y_square):
            for y in range(1, p//2 + 1):
                m = modular_exponentiation(y,2,p)
                if m == y_square:
                    return (x, y)
                
def is_primitive_root(p, a):
    if a == 0 or a == 1:
        return False
    factors = set()
    n = p - 1
    d = 2
    while d * d <= n:
        while (n % d) == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    for factor in factors:
        if pow(a, (p - 1) // factor, p) == 1:
            return False
    return True