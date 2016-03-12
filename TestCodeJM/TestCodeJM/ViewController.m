//
//  ViewController.m
//  TestCodeJM
//
//  Created by szalarm on 16/2/29.
//  Copyright © 2016年 szalarm. All rights reserved.
//

#import "ViewController.h"
//引用类库-fno-objc-arc
//#import "GTMBase64.h"
//引用服务
#import "ServerForCodeText.h"
//
#import "NSData+CCCryptUtil.h"
#import "NSString+CCCryptUtil.h"
//Test key
#define kTestKey @"123456" //测试key
//aes 加密
#import "NSString+AES.h"

@interface ViewController ()
{
}
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)dobase64EnCode:(id)sender {
    
    NSString *str = self.mUiInputTextField.text;
//    NSData *data= [str dataUsingEncoding:NSUTF8StringEncoding];
//    
//    // Encode
//    data = [GTMBase64 encodeData:data];
//    NSString *encodeStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
//    NSLog(@"%@",encodeStr);
    NSString * tEnStr= [ServerForCodeText EncodeWithBase64:str];
    self.mUiOutPutTextField.text=tEnStr;
}

- (IBAction)dobase64DisCode:(id)sender {
    NSString * encodeStr= self.mUiOutPutTextField.text;
//    NSData *data= [encodeStr dataUsingEncoding:NSUTF8StringEncoding];
//    // Decode
//    data = [GTMBase64 decodeData:data];
//    
//    NSString *retStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
//    NSLog(@"%@",retStr);
     NSString * tDeStr= [ServerForCodeText DecodeWithBase64:encodeStr];
    self.mUiOutPutTextField.text=tDeStr;

}

- (IBAction)doAesEnCode:(id)sender {
    NSString *str = self.mUiInputTextField.text;
//    NSString * tEnStr=[NSString encryptString:str Key:[ServerForCodeText EncodeMd5FromString:kTestKey]];//或者[kTestKey md5]
    NSString * tEnStr=[ServerForCodeText EncodeWithAESDefKeyFromString:str];
    self.mUiOutPutTextField.text=tEnStr;
}

- (IBAction)doAesDeCode:(id)sender {
    NSString *str = self.mUiOutPutTextField.text;
//    NSString * tDeStr= [NSString decryptString:str Key:[kTestKey md5]];
    NSString * tDeStr= [ServerForCodeText DecodeWithAESDefKeyFromString:str];
    self.mUiOutPutTextField.text=tDeStr;
//    NSString * deCodeStr=[NSString AES256Decrypt:gData withKey:[kTestKey md5]];
//    self.mUiOutPutTextField.text=deCodeStr;
    
}

- (IBAction)doMd5Encode:(id)sender {
    NSString *str = self.mUiInputTextField.text;
    NSString * tMd5Str= [ServerForCodeText EncodeMd5FromString:str];
    self.mUiOutPutTextField.text=tMd5Str;
}
@end
