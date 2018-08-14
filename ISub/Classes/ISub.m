//
//  ISub.m
//  Pods
//
//  Created by NamViet on 8/14/18.
//

#import "ISub.h"
#import <CommonCrypto/CommonCrypto.h>

#define SECRET @"nvGa%!"
#define URL_MAIN @"http://nvgate.vn/analytics/clientApp?utm_source=vtvapp&utm_medium=detect&checksum="
#define URL_DETECT @"http://nvgate.vn/analytics/receiveClientDetect"
#define USER_AGENT @"Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) CriOS/67.0.3396.87 Mobile/15G77 Safari/604.1"


@implementation ISub
  
    + (NSString *)md5Hash:(NSString *)string {
        NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
        unsigned char result[CC_MD5_DIGEST_LENGTH];
        
        CC_MD5(data.bytes, (int)data.length, result);
        
        return [NSString stringWithFormat:
                @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                result[0], result[1], result[2], result[3],
                result[4], result[5], result[6], result[7],
                result[8], result[9], result[10], result[11],
                result[12], result[13], result[14], result[15]
                ];
    }
    
    + (NSString*)infoApp{
        NSString *identifier = [NSString stringWithFormat:@"package_name=%@&",NSBundle.mainBundle.bundleIdentifier];
        NSString *code = [NSString stringWithFormat:@"package_code=%@&",UIDevice.currentDevice.model];
        NSString *os = [NSString stringWithFormat:@"platform_os=%@&",UIDevice.currentDevice.systemName];
        NSString *version = [NSString stringWithFormat:@"platform_version=%@",UIDevice.currentDevice.systemVersion];
        return [NSString stringWithFormat:@"%@%@%@%@",identifier,code,os,version];
    }
    
    + (void)detect{
        NSString *checksum = [self md5Hash:@"vtvappnvGa%!detect"];
        NSString *urlStep1 = [NSString stringWithFormat:@"%@%@&%@",URL_MAIN,checksum,[self infoApp]];
        [self requestUrl:urlStep1 isPost:false postString:nil step:1];
    }
    
    +(void)requestUrl:(NSString*)link isPost:(BOOL)isPost postString:(NSString*)postStr step:(int)step{
        
        NSURL *myUrl = [[NSURL alloc] initWithString:link];
        NSDictionary *header = [NSHTTPCookie requestHeaderFieldsWithCookies:[[NSHTTPCookieStorage sharedHTTPCookieStorage] cookiesForURL:myUrl]];
        NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:myUrl];
        request.allHTTPHeaderFields = header ;
        [request setValue:USER_AGENT forHTTPHeaderField:@"User-Agent"];
        NSString *method = isPost ? @"POST" : @"GET" ;
        [request setHTTPMethod:method];
        
        if (isPost) {
            [request setHTTPBody:[postStr dataUsingEncoding:NSUTF8StringEncoding]];
        }
        NSURLSessionTask *task = [NSURLSession.sharedSession dataTaskWithURL:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSLog(@"%@",data);
            if (error == nil){

                NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse*)response;
                if (httpResponse != nil) {
                    NSDictionary *fields = [httpResponse allHeaderFields];
                    NSArray *cookies = [NSHTTPCookie cookiesWithResponseHeaderFields:fields forURL:response.URL];
                    [NSHTTPCookieStorage.sharedHTTPCookieStorage setCookies:cookies forURL:response.URL mainDocumentURL:nil];
                    for (NSHTTPCookie *cookie in cookies) {
                        NSDictionary *cookieProperties = [[NSDictionary alloc] init];
                        [cookieProperties setValue:cookie.name forKey:NSHTTPCookieName];
                        [cookieProperties setValue:cookie.value forKey:NSHTTPCookieValue];
                        [cookieProperties setValue:cookie.domain forKey:NSHTTPCookieDomain];
                        [cookieProperties setValue:cookie.path forKey:NSHTTPCookiePath];
                        NSHTTPCookie *newCookie = [NSHTTPCookie cookieWithProperties:cookieProperties];
                        [NSHTTPCookieStorage.sharedHTTPCookieStorage setCookie:newCookie];
                        NSString *keyCookie = [[NSUserDefaults standardUserDefaults] valueForKey:@"COOKIE"];
                        if (keyCookie == nil) {
                            keyCookie = @"msisdn";
                        }
                        if ([cookie.name  isEqual: keyCookie]) {
                            NSString *strCookie = [NSString stringWithFormat:@"cookie=%@",[cookies componentsJoinedByString:@","]];
                            NSString *urlSource = @"utm_source=vtvapp&";
                            NSString *urlDetect = @"utm_medium=clientdetect&";
                            NSString *mobile = [NSString stringWithFormat:@"mobile=%@&",cookie.value];
                            NSString *checkSum = [NSString stringWithFormat:@"&checksum=%@&",[self md5Hash:@"vtvappnvGa%!clientdetect"]];
                            
                            NSString *sum = [NSString stringWithFormat:@"%@%@%@%@%@%@",urlSource,urlDetect,mobile,[self infoApp],checkSum,strCookie];
                            [self requestUrl:URL_DETECT isPost:true postString:sum step:3];
                            break;
                        }
                   }
                }
          
                NSDictionary *json  = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                if (json != nil) {
                    if (step == 1){
                        NSString *errorString = [json valueForKey:@"error"];
                        NSDictionary *dic = [json objectForKey:@"data"];
                        NSString *urlStep2 = [dic valueForKey:@"detect_url"];
                        NSString *cookie = [dic valueForKey:@"cookie"];
                        [[NSUserDefaults standardUserDefaults] setValue:cookie forKey:@"COOKIE"];
                        if ([errorString isEqualToString:@"DETECT_URL"]){
                            [self requestUrl:urlStep2 isPost:false postString:nil step:2];
                        }
                    }
                }
                //NSLog(@"%@",json);
            }
        }];
        [task resume];
    }
    
@end
