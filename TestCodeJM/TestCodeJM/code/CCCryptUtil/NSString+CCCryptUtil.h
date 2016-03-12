//
//  NSString+CCCryptUtil.h
//  TestCodeJM
//
//  Created by szalarm on 16/2/29.
//  Copyright © 2016年 szalarm. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (CCCryptUtil)
-(NSString*) md5;
+ (NSData*)AES256Encrypt:(NSString*)strSource withKey:(NSString*)key;
+ (NSString*)AES256Decrypt:(NSData*)dataSource withKey:(NSString*)key;
@end
