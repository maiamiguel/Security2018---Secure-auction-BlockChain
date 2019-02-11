import os, platform
import logging
import OpenSSL
from PyKCS11 import *
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import unicodedata

class CitizenCard:
    # Class variables
    PKCS11_LIB_LINUX = "/usr/local/lib/libpteidpkcs11.so"
    PKCS11_LIB_MAC =  "/usr/local/lib/libpteidpkcs11.dylib" 
    PKCS11_LIB_WINDOWS = "c:\\Windows\\System32\\pteidpkcs11.dll"
    PKCS11_LIB = ""
    PKCS11_session = None
    CERTIFICATE_LABEL = "CITIZEN AUTHENTICATION CERTIFICATE"

    def __init__(self):
        # Detects the operating system
        if platform.uname()[0] == "Darwin": # MAC
            if os.path.isfile(self.PKCS11_LIB_MAC):
                print(" PKCS11 library starting on OSX!\n")
                self.PKCS11_LIB = self.PKCS11_LIB_MAC
            else:
                print(" PKCS11 library doesn't exist on OSX!\n")

        elif platform.uname()[0] == "Windows":
            if os.path.isfile(self.PKCS11_LIB_WINDOWS):
                print(" PKCS11 library starting on WINDOWS!\n")
                self.PKCS11_LIB = self.PKCS11_LIB_WINDOWS
            else:
                print("PKCS11 library doesn't exist on Windows!\n")

        else:
            if os.path.isfile(self.PKCS11_LIB_LINUX):
                print(" PKCS11 library starting on LINUX!\n")
                self.PKCS11_LIB = self.PKCS11_LIB_LINUX
            else:
                print(" PKCS11 library doesn't exist on Linux!\n")

        try:
            self.PKCS11_session = self.get_session()
            #print(self.PKCS11_session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),(CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')]))
        except Exception as e:
            print(e)

    # Gets the pkcs11 session, if there is None, one is created
    def get_session(self):
        pkcs11 = PyKCS11.PyKCS11Lib()

        if self.PKCS11_session is None:
            try:
                pkcs11.load(self.PKCS11_LIB)
                slot = pkcs11.getSlotList()
            except PyKCS11.PyKCS11Error:
                raise Exception(" Couldn't load lib and get slot list\n")

            try:
                self.PKCS11_session = pkcs11.openSession(slot[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
                return self.PKCS11_session
            except (IndexError, PyKCS11.PyKCS11Error):
                raise Exception(" Card reader not detected\n")
        else:
            return self.PKCS11_session


    # Checks if the citizen card is detected
    def citizen_card_detected(self):
        return False if self.PKCS11_session is None else True
    
    # Digest the user's certificate public key
    def get_digest(self, certificate):
        try:
            pK = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
            digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
            digest.update(pK)
            return digest.finalize()
        except Exception as e:
            log(logging.ERROR, e)
            return None

    # Extract the certificates from the Citizen Card
    def extract_certificates(self):
        session = self.PKCS11_session

        # Name of the directory where the certificates will be stored
        path = "client_certificates"
        # Create the directory
        if not os.path.exists(path):
            print(" Creating directory to store certificates\n")
            os.mkdir(path)

        # Name of the directory where the certificate is stored
        path = os.path.join(path)
        # Create the directory
        if not os.path.exists(path):
            print("Creating directory to store user's certificates\n")
            os.mkdir(path)

        if session is not None:
            # Find all the certificates
            objects = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])

            for obj in objects:
                # Obtain attributes from certificate
                try:
                    attributes = session.getAttributeValue(obj, [PyKCS11.CKA_VALUE])[0]
                except PyKCS11.PyKCS11Error as e:
                    continue

                # Load certificate from DER format
                cert = x509.load_der_x509_certificate(bytes(attributes), default_backend())
                # Obtain certificate's subject
                subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                # Obtain certificate's issuer
                issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                try:
                    # 
                    if "EC de Autenticação do Cartão de Cidadão"in subject or "EC de Autenticação do Cartão de Cidadão" in issuer:
                        # Create the directory
                        if not os.path.exists(os.path.join(path,"ECs de Autenticação")):
                            os.mkdir(os.path.join(path,"ECs de Autenticação"))
                        # Save certificate in directory
                        open(path+"/ECs de Autenticação/"+str(subject)+".cer", "wb").write(cert.public_bytes(Encoding.DER))
                    elif "EC de Assinatura Digital Qualificada do Cartão de Cidadão" in subject or "EC de Assinatura Digital Qualificada do Cartão de Cidadão" in issuer:
                        # Create the directory
                        if not os.path.exists(os.path.join(path,"ECs de Assinatura Digital")):
                            os.mkdir(os.path.join(path,"ECs de Assinatura Digital"))
                        # Save certificate in directory
                        open(path+"/ECs de Assinatura Digital/"+str(subject)+".cer","wb").write(cert.public_bytes(Encoding.DER))
                    else:
                        # Save certificate in directory
                        if not os.path.isfile(path+"/"+str(subject)+".cer"):
                            open(path+"/"+str(subject)+".cer", "wb").write(
                                cert.public_bytes(Encoding.DER))
                except Exception as e:
                    log(logging.ERROR, e)

    def getCertificate(self,typeOfCert):
        session = self.PKCS11_session
        certHandle = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),(CKA_LABEL, 'CITIZEN ' + str(typeOfCert) + ' CERTIFICATE')])[0]
        return bytes(session.getAttributeValue( certHandle, [CKA_VALUE], True )[0])

    # Get the chain of a given certificate
    def getChain(self, cert):
        path = os.path.join("client_certificates")
        cert = open(path+"/ECs de Autenticação/"+cert+".cer", "rb").read()

        # Start chain
        chain = []

        # Get issuer
        issuer = self.getIssuer(cert)

        trusted_certs = [f for f in os.listdir("client_certificates") if os.path.isfile(os.path.join("client_certificates", f))]
        
        while True:
            try:
                chain.append(open(os.path.join(path, issuer+".cer"), "rb").read())
            except FileNotFoundError:
                chain.append(open(os.path.join(path, "ECs de Autenticação/" +issuer+".cer"), "rb").read())

            cert = chain[-1]
            
            issuer = self.getIssuer(cert)
            if issuer == self.getSubject(cert):
                break
        
        return chain

    # Get the issuer of a given certificate
    def getIssuer(self, cert):
        certificate = x509.load_der_x509_certificate(cert, default_backend())
        issuer = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return issuer

    # Get the subject of a given certificate
    def getSubject(self, cert):
        certificate = x509.load_der_x509_certificate(cert, default_backend())
        subject = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return subject   

    # Get a smartCard private Key
    def get_PrivKey(self, typeOfKey):
        try:
            privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            return privKey
        except Exception as e:
            print("CITIZEN ")
            print(e)

    # Sign a message with the private citizen authentication key
    def sign(self, msg):
        if self.PKCS11_session is not None:
            try:
                label = "CITIZEN AUTHENTICATION KEY"
                privK = self.PKCS11_session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, label)])[0]
                mechanism = PyKCS11.Mechanism(CKM_SHA1_RSA_PKCS)
                return bytes(self.PKCS11_session.sign(privK, msg, mechanism))
            except PyKCS11.PyKCS11Error as e:
                print( "Could not sign the message: ", e )
            except IndexError:
                print( "CITIZEN AUTHENTICATION PRIVATE KEY not found\n" )



    # Verify a certificate and its chain
    def verify(self, certificate, chain):
        
        # Check if certificate is in trusted certificates list
        # Transform bytes into certificate
        cert = x509.load_der_x509_certificate(certificate, default_backend())
        cert_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value+".cer"

        # Get list of trusted certifiates by the client        
        trusted_certs = [f for f in os.listdir("client_trusted_certs") if os.path.isfile(os.path.join("client_trusted_certs", f))]
        
        if cert_name in trusted_certs:
            if cert == x509.load_der_x509_certificate(open(os.path.join("client_trusted_certs", cert_name),"rb").read(),default_backend()):
                print(" > CERTIFICATE \'{}\' IS VALID".format(cert_name))
                #log(logging.DEBUG, "Certificate {} is Valid\n".format(cert_name))
                return

        # Convert the certificates into a crypto.x509 object
        tmp = []
        for i in chain:
            tmp.append(x509.load_der_x509_certificate(i, default_backend()))

        # Verify the chain
        if len(chain) != 0:
            try:
                self.verify(chain[0],chain[1:])
            except Exception as e:
                raise Exception(e)