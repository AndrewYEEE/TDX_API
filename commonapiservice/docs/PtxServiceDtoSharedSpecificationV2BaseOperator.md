# PtxServiceDtoSharedSpecificationV2BaseOperator

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ProviderID** | **string** | 資料提供平台代碼 | [default to null]
**OperatorID** | **string** | 營運業者代碼 | [default to null]
**OperatorName** | [***AllOfPtxServiceDtoSharedSpecificationV2BaseOperatorOperatorName**](AllOfPtxServiceDtoSharedSpecificationV2BaseOperatorOperatorName.md) | 營運業者名稱 | [default to null]
**OperatorPhone** | **string** | 營運業者連絡電話 | [optional] [default to null]
**OperatorEmail** | **string** | 營運業者電子信箱 | [optional] [default to null]
**OperatorUrl** | **string** | 營運業者網址鏈結 | [optional] [default to null]
**ReservationUrl** | **string** | 訂票網址鏈結 | [optional] [default to null]
**ReservationPhone** | **string** | 訂票連絡電話 | [optional] [default to null]
**OperatorCode** | **string** | 營運業者簡碼 | [optional] [default to null]
**AuthorityCode** | **string** | 營運業者業管機關簡碼(對於於公路客運/國道客運而言為THB) | [default to null]
**SubAuthorityCode** | **string** | 營運業者所屬業管子機關簡碼(對於公路客運/國道客運路線而言為區監理所如THB-VO10-1..等) | [optional] [default to null]
**OperatorNo** | **string** | 營運業者編號[交通部票證資料系統定義] | [default to null]
**UpdateTime** | [**time.Time**](time.Time.md) | 資料更新日期時間(ISO8601格式:yyyy-MM-ddTHH:mm:sszzz) | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

