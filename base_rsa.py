from Crypto.Util.number import getPrime, inverse, GCD

def main():
    # Generate RSA key pair (p and q)
    p = getPrime(1024)
    q = getPrime(1024)
    
    # Check if p and q are coprime
    if GCD(p, q) != 1:
        print("p and q are not coprime. Exiting.")
        return
    
    # Get Public key (n)
    n = p * q
    
    # Public exponent (e)
    e = 65537  
    
    # Get Private key (d)
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    
    print(f"p: {p} \nq: {q} \nn: {n} \ne: {e} \nphi: {phi} \nd: {d}")

if __name__ == "__main__":
    main()
