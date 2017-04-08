#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

/* Begin global declarations */

// Global constants used for symmetric key algorithm choice and
// chosen digest.

// The chosen symmetric key and digest algorithm chosen for this sample is AES and SHA1.
// The reasoning behind this was due to the fact that the iPhone and iPod touch have
// hardware accelerators for those particular algorithms and therefore are energy efficient.

#define kChosenCipherBlockSize	kCCBlockSizeAES128
#define kChosenCipherKeySize	kCCKeySizeAES128
#define kChosenDigestLength		CC_SHA1_DIGEST_LENGTH

// Global constants for padding schemes.
#define	kPKCS1					11
#define kTypeOfWrapPadding		kSecPaddingPKCS1
#define kTypeOfSigPadding		kSecPaddingPKCS1SHA1

// constants used to find public, private, and symmetric keys.
#define kPublicKeyTag			"com.ums.publickey"
#define kPrivateKeyTag			"com.ums.privatekey"
#define kSymmetricKeyTag		"com.ums.symmetrickey"

@interface CFPSecKeyWrapper : NSObject

@property (nonatomic, retain) NSData * publicTag;
@property (nonatomic, retain) NSData * privateTag;
@property (nonatomic, retain) NSData * symmetricTag;
@property (nonatomic, assign) CFDataRef * symmetricKeyRef;

+ (CFPSecKeyWrapper *)shared;
- (void)generateKeyPair:(NSUInteger)keySize;
- (void)deleteAsymmetricKeys;
- (void)removePeerPublicKey:(NSString *)peerName;
- (NSData *)getSignatureBytes:(NSData *)plainText;
- (NSData *)getHashBytes:(NSData *)plainText;
- (BOOL)verifySignature:(NSData *)plainText secKeyRef:(SecKeyRef)publicKey signature:(NSData *)sig;
- (SecKeyRef)getPublicKeyRef;
- (NSData *)getPublicKeyBits;
- (SecKeyRef)getPrivateKeyRef;
- (CFTypeRef)getPersistentKeyRefWithKeyRef:(SecKeyRef)keyRef;
- (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef;


@end
