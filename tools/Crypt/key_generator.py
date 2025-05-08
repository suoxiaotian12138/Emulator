from cryptography.hazmat.primitives.asymmetric import ec







def SECP256R1_setup():
    ''' setup the parameters of the loopix Crypto-system '''
    curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    generator = public_key.public_numbers().x, public_key.public_numbers().y
    return curve, private_key, public_key, generator


