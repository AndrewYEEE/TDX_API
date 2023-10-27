package main

// import (
// 	"fmt"
// 	"time"
// 	"net/http"
// 	"crypto/sha1"
// 	"crypto/hmac"
// 	"encoding/base64"
// 	"io/ioutil"
// )

// type PTXService struct{
// 	AppID string
// 	AppKey string
// }

// func AuthGenerator(APPID, APPKEY string) (string, string){
// 	xdate, sign := signGenerator(APPID, APPKEY);
// 	auth := "hmac username=\"" + APPID + "\", algorithm=\"hmac-sha1\", headers=\"x-date\", signature=\"" + sign + "\""
	
// 	return xdate, auth
// }

// func signGenerator(APPID, APPKEY string) (string, string){
// 	xdate := getServerTime()
// 	encryptXdate := "x-date: " + xdate
// 	encryptSign := hmac_sha1_generator(encryptXdate, APPKEY)

// 	return xdate, encryptSign
// }

// func getServerTime() string {
// 	//ptx platform time is GMT 0.
// 	return time.Now().UTC().Format(http.TimeFormat)
// }

// func hmac_sha1_generator(enc_xdate string, appkey string) string{
// 	key := []byte(appkey)
// 	mac := hmac.New(sha1.New, key)
// 	mac.Write([]byte(enc_xdate))
// 	mac_encrypted := base64.StdEncoding.EncodeToString(mac.Sum(nil))
// 	return mac_encrypted
// }

// func Get(p PTXService, url string) string{

// 	//AuthGenerator function is form ./ptxAuthGrenerator.go
// 	xdate, auth := AuthGenerator(p.AppID, p.AppKey);

// 	client := &http.Client{}
// 	req, _ := http.NewRequest("GET", url, nil)
// 	req.Header.Set("x-date", xdate)
// 	req.Header.Set("Authorization", auth)
// 	res, _ := client.Do(req)

// 	defer res.Body.Close()
// 	body, _ := ioutil.ReadAll(res.Body)

// 	return string(body)
// }

// func main(){
// 	APPID := "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF";
// 	APPKEY := "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF";
	
// 	ptx := PTXService{
// 		APPID,
// 		APPKEY,
// 	}

// 	//usage
// 	fmt.Println(Get(ptx, "https://ptx.transportdata.tw/MOTC/v2/Rail/TRA/Station?$top=10&$format=JSON"))
// }


import (
    // "context"
    "fmt"
    "log"
    // "golang.org/x/oauth2"
	"net/http"
	"io/ioutil"
	// "bytes"
	"strings"
	"encoding/json"
	// "reflect"
	CAS "./commonapiservice/CAS" 
)
var APP_ID string =""
var APP_KEY string =""
var TDX_AUTH_url string = "https://tdx.transportdata.tw/auth/realms/TDXConnect/protocol/openid-connect/token"
//var data_url string = "https://tdx.transportdata.tw/api/basic/v3/Rail/TRA/DailyTrainTimetable/OD/{0}/to/{1}/{2}$format=JSON".format(OriginStationID, DestinationStationID, TrainDate)

func main() {
	CASClient := CAS.NewAPIClient()
	log.Println(CASClient)
    // // configure the OAuth2 client
    // config := &oauth2.Config{
    //     ClientID:     APP_ID,
    //     ClientSecret: APP_KEY,
    //     TokenURL:     auth_url,
    // }

    // // get an OAuth2 token
    // token, err := config.ClientCredentialsToken(context.Background())
    // if err != nil {
    //     log.Fatal(err)
    // }

    // print the token
	
    // fmt.Printf("Token: %s\n", token)

	// token, time,_ := HttpRequest_TDX_GETToken(APP_ID,APP_KEY,TDX_AUTH_url)
	// log.Println(token, time)
}


func HttpRequest_POST(url string ){
	var err error = nil
	
	var client http.Client
	client = http.Client{}
	payload := strings.NewReader("grant_type=client_credentials&client_id=XXX&client_secret=XXX")
	req, err := http.NewRequest("POST", url,payload)
	if err != nil {
		//panic(err)
		log.Println("[ERROR] ", err)
		return  
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// req.Header.Set("grant_type", "client_credentials")
	// req.Header.Set("client_id", APP_ID)
	// req.Header.Set("client_secret", APP_KEY)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(body))
	return
}


func HttpRequest_TDX_GETToken(client_id string, client_secret string, TDX_AUTH_url string) (access_token string, expires_in string ,err error){
	err = nil
	access_token = ""
	expires_in = "0"


	var client http.Client
	client = http.Client{}
	data := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s",client_id,client_secret)
	payload := strings.NewReader(data)
	req, err := http.NewRequest("POST", TDX_AUTH_url, payload)
	if err != nil {
		//panic(err)
		log.Println("[ERROR] ", err)
		return  access_token, expires_in, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// req.Header.Set("grant_type", "client_credentials")
	// req.Header.Set("client_id", APP_ID)
	// req.Header.Set("client_secret", APP_KEY)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return access_token, expires_in, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return access_token, expires_in, err
	}

	if res.StatusCode != 200 {
		fmt.Println(res.StatusCode)
		fmt.Println(http.StatusText(res.StatusCode))
		return access_token, expires_in, err
	}
	
	
	var TDX_AUTH_Reply interface{}
	if err = json.Unmarshal([]byte(body), &TDX_AUTH_Reply); err != nil {
		log.Println("[ERROR] The reply JSON from API have some problem!!")
		fmt.Println("Reply Data: ", data)
		return access_token, expires_in, err
	}
	var m map[string]interface{}
	var ok bool 
	if m, ok = TDX_AUTH_Reply.(map[string]interface{}); !ok {
		log.Fatal("failed to type assert data")
		return access_token, expires_in, err
	}
	// for k,v:=range m {
	// 	fmt.Println("Key:", k, "type:",reflect.TypeOf(k) ,"Value:", v, "type:",reflect.TypeOf(v) )
	// }
	
	if _, ok := m["access_token"]; ok {
		access_token = fmt.Sprintf("%s", m["access_token"])
	}else{
		log.Fatal("failed to get access_token from map")
		return access_token, expires_in, err
	}

	if _, ok := m["expires_in"]; ok {
		expires_in = fmt.Sprintf("%v", m["expires_in"])
	}else{
		log.Fatal("failed to get expires_in from map")
		return access_token, expires_in, err
	}
	

	return access_token, expires_in, err
}