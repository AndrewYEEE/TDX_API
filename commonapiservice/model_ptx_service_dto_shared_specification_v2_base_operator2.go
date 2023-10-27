/*
 * 共通資料-公共運輸
 *
 *  --- ##### API線上說明(Swagger UI)使用流程與注意事項： 1. 若不使用API金鑰呼叫API，則僅能透過瀏覽器呼叫`【基礎】`服務 ，且每個呼叫來源端IP的上限為每日50次。 2. `【進階】`、`【加值】`、`【歷史】`、`【MaaS】`服務需加入會員並取得API金鑰之後才能使用。 3. 欲使用API金鑰呼叫API，需[註冊為TDX會員](/register)，並於會員中心取得API金鑰。 4. 註冊為會員之後，至[【會員專區-資料服務-服務金鑰】](/user/dataservice/key)功能頁面，從預設金鑰(或建立新的金鑰)取得Client Id和Client Secret資訊。 5. 點選Swagger UI上的Authorize按鈕，依指示填入Client Id和Client Secret資訊並進行驗證，驗證完成後可開始於Swagger UI使用API。 6. 欲透過程式介接API，可參考[範例程式](https://github.com/tdxmotc/SampleCode)。 7. 為確保系統資源使用的合理分配與避免遭受濫用，於Swagger UI上使用API與程式介接API的行為將被記錄並定期做檢視。  ##### API呼叫次數限制: 1. 若不使用API金鑰呼叫API，則僅能透過瀏覽器呼叫`【基礎】`服務 ，且每個呼叫來源端IP的上限為每日50次。 2. 使用API金鑰呼叫API，每個呼叫來源端IP呼叫次數限制為50次/秒 (無每日上限)。  API OAS文本 :[請點我](https://tdx.transportdata.tw/webapi/File/Swagger/V3/9aa23880-013d-4919-be46-3d748d7001e4)
 *
 * API version: v3
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger

type PtxServiceDtoSharedSpecificationV2BaseOperator2 struct {
}
