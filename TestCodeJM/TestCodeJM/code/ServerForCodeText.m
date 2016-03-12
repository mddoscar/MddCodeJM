//
//  ServerForCodeText.m
//  TestCodeJM
//
//  Created by szalarm on 16/2/29.
//  Copyright © 2016年 szalarm. All rights reserved.
//

#import "ServerForCodeText.h"
//引用类库-fno-objc-arc
#import "GTMBase64.h"
//aes封装
#import "NSString+AES.h"
//aes加密
#import <CommonCrypto/CommonCryptor.h>
//md5
#import <CommonCrypto/CommonDigest.h>

//默认key
#define kDefRawKey @"mddoscar" 
//默认key源(要32位的)


@implementation ServerForCodeText
#pragma mark public
+(NSString *) EncodeWithBase64:(NSString *) pRawStr
{
    NSData *data= [pRawStr dataUsingEncoding:NSUTF8StringEncoding];
    
    // Encode
    data = [GTMBase64 encodeData:data];
    NSString *encodeStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"%@",encodeStr);
    return encodeStr;

}
+(NSString *) DecodeWithBase64:(NSString *) pBase64Str
{
    NSData *data= [pBase64Str dataUsingEncoding:NSUTF8StringEncoding];
    // Decode
    data = [GTMBase64 decodeData:data];
    
    NSString *retStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"%@",retStr);
    return retStr;
}

+(NSString*) EncodeMd5FromString:(NSString *)pRawString {
//    NSData *dataSource = [pRawString dataUsingEncoding:NSUTF8StringEncoding];
    const char * cStrValue = [pRawString UTF8String];
    unsigned char theResult[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStrValue, strlen(cStrValue), theResult);
    return [NSString stringWithFormat:@"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
            theResult[0], theResult[1], theResult[2], theResult[3],
            theResult[4], theResult[5], theResult[6], theResult[7],
            theResult[8], theResult[9], theResult[10], theResult[11],
            theResult[12], theResult[13], theResult[14], theResult[15]];
}
+(NSData*)EncodeWithAES256tWithKey:(NSString*)key mFromString:(NSString *)pStr{
    //数据源
    NSData *resourceData =[pStr dataUsingEncoding:NSUTF8StringEncoding];
    char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [pStr length];
    
    size_t bufferSize           = dataLength + kCCBlockSizeAES128;
    void* buffer                = malloc(bufferSize);
    
    size_t numBytesEncrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [resourceData bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer);
    return nil;
}

+ (NSData*)DecodeWithAES256DecryptWithKey:(NSString*)key  mFromString:(NSString *)pStr{
    //数据源
    NSData *resourceData =[pStr dataUsingEncoding:NSUTF8StringEncoding];
    char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [pStr length];
    
    size_t bufferSize           = dataLength + kCCBlockSizeAES128;
    void* buffer                = malloc(bufferSize);
    
    size_t numBytesDecrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [resourceData bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}
+(NSString *)EncodeWithAESFromString:(NSString *)pOriData Key:(NSString *)pkey
{
  NSString * rEncodeStr=[NSString encryptString:pOriData Key:pkey];
  return  rEncodeStr;
}
+ (NSString *)DecodeWithAESFromString:(NSString *)pDecData  Key:(NSString *)pkey
{
    NSString * rDecodeStr= [NSString decryptString:pDecData Key:pkey];
    return  rDecodeStr;
}
+(NSString *)EncodeWithAESDefKeyFromString:(NSString *)pOriData
{
    NSString * tDefKEy=[[self class ] DefPrivateKey];
    return [[self class] EncodeWithAESFromString:pOriData Key:tDefKEy];
}
+ (NSString *)DecodeWithAESDefKeyFromString:(NSString *)pDecData
{
    NSString * tDefKEy=[[self class ] DefPrivateKey];
    return [[self class] DecodeWithAESFromString:pDecData Key:tDefKEy];
}//默认key
//默认key
+(NSString *) DefPrivateKey
{
    return [[self class]EncodeMd5FromString:kDefRawKey];
}
//替换非utf8字符
//注意：如果是三字节utf-8，第二字节错误，则先替换第一字节内容(认为此字节误码为三字节utf8的头)，然后判断剩下的两个字节是否非法；
+(NSData *)replaceNoUtf8:(NSData *)data
{
    char aa[] = {'A','A','A','A','A','A'};                      //utf8最多6个字符，当前方法未使用
    NSMutableData *md = [NSMutableData dataWithData:data];
    int loc = 0;
    while(loc < [md length])
    {
        char buffer;
        [md getBytes:&buffer range:NSMakeRange(loc, 1)];
        if((buffer & 0x80) == 0)
        {
            loc++;
            continue;
        }
        else if((buffer & 0xE0) == 0xC0)
        {
            loc++;
            [md getBytes:&buffer range:NSMakeRange(loc, 1)];
            if((buffer & 0xC0) == 0x80)
            {
                loc++;
                continue;
            }
            loc--;
            //非法字符，将这个字符（一个byte）替换为A
            [md replaceBytesInRange:NSMakeRange(loc, 1) withBytes:aa length:1];
            loc++;
            continue;
        }
        else if((buffer & 0xF0) == 0xE0)
        {
            loc++;
            [md getBytes:&buffer range:NSMakeRange(loc, 1)];
            if((buffer & 0xC0) == 0x80)
            {
                loc++;
                [md getBytes:&buffer range:NSMakeRange(loc, 1)];
                if((buffer & 0xC0) == 0x80)
                {
                    loc++;
                    continue;
                }
                loc--;
            }
            loc--;
            //非法字符，将这个字符（一个byte）替换为A
            [md replaceBytesInRange:NSMakeRange(loc, 1) withBytes:aa length:1];
            loc++;
            continue;
        }
        else
        {
            //非法字符，将这个字符（一个byte）替换为A
            [md replaceBytesInRange:NSMakeRange(loc, 1) withBytes:aa length:1];
            loc++;
            continue;
        }
    }
    
    return md;
}
/*
 按照utf8格式标准
 Unicode/UCS-4
 bit数
 UTF-8
 byte数
 范围(16进制)
 0000 ~
 007F
 0~7
 0XXX XXXX
 1
 0x - 7x
 0080 ~
 07FF
 8~11
 110X XXXX
 10XX XXXX
 2
 Cx 8x - Dx Bx
 0800 ~
 FFFF
 12~16
 1110XXXX
 10XX XXXX
 10XX XXXX
 3
 Ex 8x 8x - Ex Bx Bx
 1 0000 ~
 1F FFFF
 17~21
 1111 0XXX
 10XX XXXX
 10XX XXXX
 10XX XXXX
 4
 F8 8x 8x 8x 8x - FB Bx Bx Bx Bx
 20 0000 ~
 3FF FFFF
 22~26
 1111 10XX
 10XX XXXX
 10XX XXXX
 10XX XXXX
 10XX XXXX
 5
 FC 8x 8x 8x 8x 8x - FD Bx Bx Bx Bx Bx
 400 0000 ~
 7FFF FFFF
 27~31
 1111 110X
 10XX XXXX
 10XX XXXX
 10XX XXXX
 10XX XXXX
 10XX XXXX
 6

 */

@end
