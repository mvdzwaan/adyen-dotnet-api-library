/*
* Adyen Checkout API
*
*
* The version of the OpenAPI document: 71
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Adyen.Model;
using Adyen.Model.Checkout;

namespace Adyen.Service.Checkout
{
    /// <summary>
    /// ClassicCheckoutSDKService Interface
    /// </summary>
    public interface IClassicCheckoutSDKService
    {
        /// <summary>
        /// Create a payment session
        /// </summary>
        /// <param name="paymentSetupRequest"><see cref="PaymentSetupRequest"/> - </param>
        /// <param name="requestOptions"><see cref="RequestOptions"/> - Additional request options.</param>
        /// <returns><see cref="PaymentSetupResponse"/>.</returns>
        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        Model.Checkout.PaymentSetupResponse PaymentSession(PaymentSetupRequest paymentSetupRequest = default, RequestOptions requestOptions = default);
        
        /// <summary>
        /// Create a payment session
        /// </summary>
        /// <param name="paymentSetupRequest"><see cref="PaymentSetupRequest"/> - </param>
        /// <param name="requestOptions"><see cref="RequestOptions"/> - Additional request options.</param>
        /// <param name="cancellationToken"> A CancellationToken enables cooperative cancellation between threads, thread pool work items, or Task objects.</param>
        /// <returns>Task of <see cref="PaymentSetupResponse"/>.</returns>
        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        Task<Model.Checkout.PaymentSetupResponse> PaymentSessionAsync(PaymentSetupRequest paymentSetupRequest = default, RequestOptions requestOptions = default, CancellationToken cancellationToken = default);
        
        /// <summary>
        /// Verify a payment result
        /// </summary>
        /// <param name="paymentVerificationRequest"><see cref="PaymentVerificationRequest"/> - </param>
        /// <param name="requestOptions"><see cref="RequestOptions"/> - Additional request options.</param>
        /// <returns><see cref="PaymentVerificationResponse"/>.</returns>
        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        Model.Checkout.PaymentVerificationResponse VerifyPaymentResult(PaymentVerificationRequest paymentVerificationRequest = default, RequestOptions requestOptions = default);
        
        /// <summary>
        /// Verify a payment result
        /// </summary>
        /// <param name="paymentVerificationRequest"><see cref="PaymentVerificationRequest"/> - </param>
        /// <param name="requestOptions"><see cref="RequestOptions"/> - Additional request options.</param>
        /// <param name="cancellationToken"> A CancellationToken enables cooperative cancellation between threads, thread pool work items, or Task objects.</param>
        /// <returns>Task of <see cref="PaymentVerificationResponse"/>.</returns>
        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        Task<Model.Checkout.PaymentVerificationResponse> VerifyPaymentResultAsync(PaymentVerificationRequest paymentVerificationRequest = default, RequestOptions requestOptions = default, CancellationToken cancellationToken = default);
        
    }
    
    /// <summary>
    /// Represents a collection of functions to interact with the ClassicCheckoutSDKService API endpoints
    /// </summary>
    public class ClassicCheckoutSDKService : AbstractService, IClassicCheckoutSDKService
    {
        private readonly string _baseUrl;
        
        public ClassicCheckoutSDKService(Client client) : base(client)
        {
            _baseUrl = CreateBaseUrl("https://checkout-test.adyen.com/v71");
        }
        
        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        public Model.Checkout.PaymentSetupResponse PaymentSession(PaymentSetupRequest paymentSetupRequest = default, RequestOptions requestOptions = default)
        {
            return PaymentSessionAsync(paymentSetupRequest, requestOptions).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        public async Task<Model.Checkout.PaymentSetupResponse> PaymentSessionAsync(PaymentSetupRequest paymentSetupRequest = default, RequestOptions requestOptions = default, CancellationToken cancellationToken = default)
        {
            var endpoint = _baseUrl + "/paymentSession";
            var resource = new ServiceResource(this, endpoint);
            return await resource.RequestAsync<Model.Checkout.PaymentSetupResponse>(paymentSetupRequest.ToJson(), requestOptions, new HttpMethod("POST"), cancellationToken).ConfigureAwait(false);
        }
        
        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        public Model.Checkout.PaymentVerificationResponse VerifyPaymentResult(PaymentVerificationRequest paymentVerificationRequest = default, RequestOptions requestOptions = default)
        {
            return VerifyPaymentResultAsync(paymentVerificationRequest, requestOptions).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        [Obsolete("Deprecated since Adyen Checkout API v37.")]
        public async Task<Model.Checkout.PaymentVerificationResponse> VerifyPaymentResultAsync(PaymentVerificationRequest paymentVerificationRequest = default, RequestOptions requestOptions = default, CancellationToken cancellationToken = default)
        {
            var endpoint = _baseUrl + "/payments/result";
            var resource = new ServiceResource(this, endpoint);
            return await resource.RequestAsync<Model.Checkout.PaymentVerificationResponse>(paymentVerificationRequest.ToJson(), requestOptions, new HttpMethod("POST"), cancellationToken).ConfigureAwait(false);
        }
    }
}