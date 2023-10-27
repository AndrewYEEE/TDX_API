# {{classname}}

All URIs are relative to *https://tdx.transportdata.tw/api/basic*

Method | HTTP request | Description
------------- | ------------- | -------------
[**BasicApiAuthority2160**](CommonApi.md#BasicApiAuthority2160) | **Get** /v2/Basic/Authority | 取得業管機關資料
[**BasicApiOperator2162**](CommonApi.md#BasicApiOperator2162) | **Get** /v2/Basic/Operator | 取得營運業者資料
[**BasicApiProvider2161**](CommonApi.md#BasicApiProvider2161) | **Get** /v2/Basic/Provider | 取得資料提供平台資料

# **BasicApiAuthority2160**
> []PtxServiceDtoSharedSpecificationV2BaseAuthority BasicApiAuthority2160(ctx, format, optional)
取得業管機關資料

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **format** | **string**| 指定來源格式 | 
 **optional** | ***CommonApiBasicApiAuthority2160Opts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a CommonApiBasicApiAuthority2160Opts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **select_** | **optional.String**| 挑選 | 
 **filter** | **optional.String**| 過濾 | 
 **orderby** | **optional.String**| 排序 | 
 **top** | **optional.Int32**| 取前幾筆 | [default to 30]
 **skip** | **optional.String**| 跳過前幾筆 | 

### Return type

[**[]PtxServiceDtoSharedSpecificationV2BaseAuthority**](PTX.Service.DTO.Shared.Specification.V2.Base.Authority.md)

### Authorization

[TDX](../README.md#TDX)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/xml

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **BasicApiOperator2162**
> []PtxServiceDtoSharedSpecificationV2BaseOperator BasicApiOperator2162(ctx, format, optional)
取得營運業者資料

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **format** | **string**| 指定來源格式 | 
 **optional** | ***CommonApiBasicApiOperator2162Opts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a CommonApiBasicApiOperator2162Opts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **select_** | **optional.String**| 挑選 | 
 **filter** | **optional.String**| 過濾 | 
 **orderby** | **optional.String**| 排序 | 
 **top** | **optional.Int32**| 取前幾筆 | [default to 30]
 **skip** | **optional.String**| 跳過前幾筆 | 

### Return type

[**[]PtxServiceDtoSharedSpecificationV2BaseOperator**](PTX.Service.DTO.Shared.Specification.V2.Base.Operator.md)

### Authorization

[TDX](../README.md#TDX)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/xml

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **BasicApiProvider2161**
> []PtxServiceDtoSharedSpecificationV2BaseProvider BasicApiProvider2161(ctx, format, optional)
取得資料提供平台資料

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **format** | **string**| 指定來源格式 | 
 **optional** | ***CommonApiBasicApiProvider2161Opts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a CommonApiBasicApiProvider2161Opts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **select_** | **optional.String**| 挑選 | 
 **filter** | **optional.String**| 過濾 | 
 **orderby** | **optional.String**| 排序 | 
 **top** | **optional.Int32**| 取前幾筆 | [default to 30]
 **skip** | **optional.String**| 跳過前幾筆 | 

### Return type

[**[]PtxServiceDtoSharedSpecificationV2BaseProvider**](PTX.Service.DTO.Shared.Specification.V2.Base.Provider.md)

### Authorization

[TDX](../README.md#TDX)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/xml

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

