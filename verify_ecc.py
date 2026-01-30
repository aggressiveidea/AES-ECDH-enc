
def is_on_curve(x, y, a, b, p):
    return (y**2 - (x**3 + a*x + b)) % p == 0

def add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if x1 == x2 and y1 == y2:
        m = (3 * x1**2 + a) * pow(2 * y1, -1, p)
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, p)
    x3 = (m**2 - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def multiply(k, P, a, p):
    res = None
    base = P
    while k > 0:
        if k & 1:
            res = add(res, base, a, p)
        base = add(base, base, a, p)
        k >>= 1
    return res

a, b, p = 2, 2, 17
G = (5, 1)

print(f"Checking if G{G} is on curve y^2 = x^3 + {a}x + {b} mod {p}: {is_on_curve(G[0], G[1], a, b, p)}")

points = []
for x in range(p):
    for y in range(p):
        if is_on_curve(x, y, a, b, p):
            points.append((x, y))

print(f"Total points (including infinity): {len(points) + 1}")

order = 0
curr = G
while curr is not None:
    order += 1
    curr = add(curr, G, a, p)
order += 1 # for point at infinity
print(f"Order of G: {order}")
