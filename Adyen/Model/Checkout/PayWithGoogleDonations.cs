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
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = Adyen.ApiSerialization.OpenAPIDateConverter;

namespace Adyen.Model.Checkout
{
    /// <summary>
    /// PayWithGoogleDonations
    /// </summary>
    [DataContract(Name = "PayWithGoogleDonations")]
    public partial class PayWithGoogleDonations : IEquatable<PayWithGoogleDonations>, IValidatableObject
    {
        /// <summary>
        /// The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**.
        /// </summary>
        /// <value>The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**.</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum FundingSourceEnum
        {
            /// <summary>
            /// Enum Credit for value: credit
            /// </summary>
            [EnumMember(Value = "credit")]
            Credit = 1,

            /// <summary>
            /// Enum Debit for value: debit
            /// </summary>
            [EnumMember(Value = "debit")]
            Debit = 2

        }


        /// <summary>
        /// The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**.
        /// </summary>
        /// <value>The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**.</value>
        [DataMember(Name = "fundingSource", EmitDefaultValue = false)]
        public FundingSourceEnum? FundingSource { get; set; }
        /// <summary>
        /// **paywithgoogle**
        /// </summary>
        /// <value>**paywithgoogle**</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum Paywithgoogle for value: paywithgoogle
            /// </summary>
            [EnumMember(Value = "paywithgoogle")]
            Paywithgoogle = 1

        }


        /// <summary>
        /// **paywithgoogle**
        /// </summary>
        /// <value>**paywithgoogle**</value>
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public TypeEnum? Type { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="PayWithGoogleDonations" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected PayWithGoogleDonations() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="PayWithGoogleDonations" /> class.
        /// </summary>
        /// <param name="checkoutAttemptId">The checkout attempt identifier..</param>
        /// <param name="fundingSource">The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**..</param>
        /// <param name="googlePayToken">The &#x60;token&#x60; that you obtained from the [Google Pay API](https://developers.google.com/pay/api/web/reference/response-objects#PaymentData) &#x60;PaymentData&#x60; response. (required).</param>
        /// <param name="recurringDetailReference">This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token..</param>
        /// <param name="storedPaymentMethodId">This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token..</param>
        /// <param name="threeDS2SdkVersion">Required for mobile integrations. Version of the 3D Secure 2 mobile SDK..</param>
        /// <param name="type">**paywithgoogle** (default to TypeEnum.Paywithgoogle).</param>
        public PayWithGoogleDonations(string checkoutAttemptId = default(string), FundingSourceEnum? fundingSource = default(FundingSourceEnum?), string googlePayToken = default(string), string recurringDetailReference = default(string), string storedPaymentMethodId = default(string), string threeDS2SdkVersion = default(string), TypeEnum? type = TypeEnum.Paywithgoogle)
        {
            this.GooglePayToken = googlePayToken;
            this.CheckoutAttemptId = checkoutAttemptId;
            this.FundingSource = fundingSource;
            this.RecurringDetailReference = recurringDetailReference;
            this.StoredPaymentMethodId = storedPaymentMethodId;
            this.ThreeDS2SdkVersion = threeDS2SdkVersion;
            this.Type = type;
        }

        /// <summary>
        /// The checkout attempt identifier.
        /// </summary>
        /// <value>The checkout attempt identifier.</value>
        [DataMember(Name = "checkoutAttemptId", EmitDefaultValue = false)]
        public string CheckoutAttemptId { get; set; }

        /// <summary>
        /// The &#x60;token&#x60; that you obtained from the [Google Pay API](https://developers.google.com/pay/api/web/reference/response-objects#PaymentData) &#x60;PaymentData&#x60; response.
        /// </summary>
        /// <value>The &#x60;token&#x60; that you obtained from the [Google Pay API](https://developers.google.com/pay/api/web/reference/response-objects#PaymentData) &#x60;PaymentData&#x60; response.</value>
        [DataMember(Name = "googlePayToken", IsRequired = false, EmitDefaultValue = false)]
        public string GooglePayToken { get; set; }

        /// <summary>
        /// This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.
        /// </summary>
        /// <value>This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.</value>
        [DataMember(Name = "recurringDetailReference", EmitDefaultValue = false)]
        [Obsolete("Deprecated since Adyen Checkout API v49. Use `storedPaymentMethodId` instead.")]
        public string RecurringDetailReference { get; set; }

        /// <summary>
        /// This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.
        /// </summary>
        /// <value>This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.</value>
        [DataMember(Name = "storedPaymentMethodId", EmitDefaultValue = false)]
        public string StoredPaymentMethodId { get; set; }

        /// <summary>
        /// Required for mobile integrations. Version of the 3D Secure 2 mobile SDK.
        /// </summary>
        /// <value>Required for mobile integrations. Version of the 3D Secure 2 mobile SDK.</value>
        [DataMember(Name = "threeDS2SdkVersion", EmitDefaultValue = false)]
        public string ThreeDS2SdkVersion { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class PayWithGoogleDonations {\n");
            sb.Append("  CheckoutAttemptId: ").Append(CheckoutAttemptId).Append("\n");
            sb.Append("  FundingSource: ").Append(FundingSource).Append("\n");
            sb.Append("  GooglePayToken: ").Append(GooglePayToken).Append("\n");
            sb.Append("  RecurringDetailReference: ").Append(RecurringDetailReference).Append("\n");
            sb.Append("  StoredPaymentMethodId: ").Append(StoredPaymentMethodId).Append("\n");
            sb.Append("  ThreeDS2SdkVersion: ").Append(ThreeDS2SdkVersion).Append("\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as PayWithGoogleDonations);
        }

        /// <summary>
        /// Returns true if PayWithGoogleDonations instances are equal
        /// </summary>
        /// <param name="input">Instance of PayWithGoogleDonations to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PayWithGoogleDonations input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.CheckoutAttemptId == input.CheckoutAttemptId ||
                    (this.CheckoutAttemptId != null &&
                    this.CheckoutAttemptId.Equals(input.CheckoutAttemptId))
                ) && 
                (
                    this.FundingSource == input.FundingSource ||
                    this.FundingSource.Equals(input.FundingSource)
                ) && 
                (
                    this.GooglePayToken == input.GooglePayToken ||
                    (this.GooglePayToken != null &&
                    this.GooglePayToken.Equals(input.GooglePayToken))
                ) && 
                (
                    this.RecurringDetailReference == input.RecurringDetailReference ||
                    (this.RecurringDetailReference != null &&
                    this.RecurringDetailReference.Equals(input.RecurringDetailReference))
                ) && 
                (
                    this.StoredPaymentMethodId == input.StoredPaymentMethodId ||
                    (this.StoredPaymentMethodId != null &&
                    this.StoredPaymentMethodId.Equals(input.StoredPaymentMethodId))
                ) && 
                (
                    this.ThreeDS2SdkVersion == input.ThreeDS2SdkVersion ||
                    (this.ThreeDS2SdkVersion != null &&
                    this.ThreeDS2SdkVersion.Equals(input.ThreeDS2SdkVersion))
                ) && 
                (
                    this.Type == input.Type ||
                    this.Type.Equals(input.Type)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.CheckoutAttemptId != null)
                {
                    hashCode = (hashCode * 59) + this.CheckoutAttemptId.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.FundingSource.GetHashCode();
                if (this.GooglePayToken != null)
                {
                    hashCode = (hashCode * 59) + this.GooglePayToken.GetHashCode();
                }
                if (this.RecurringDetailReference != null)
                {
                    hashCode = (hashCode * 59) + this.RecurringDetailReference.GetHashCode();
                }
                if (this.StoredPaymentMethodId != null)
                {
                    hashCode = (hashCode * 59) + this.StoredPaymentMethodId.GetHashCode();
                }
                if (this.ThreeDS2SdkVersion != null)
                {
                    hashCode = (hashCode * 59) + this.ThreeDS2SdkVersion.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.Type.GetHashCode();
                return hashCode;
            }
        }
        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            // GooglePayToken (string) maxLength
            if (this.GooglePayToken != null && this.GooglePayToken.Length > 5000)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for GooglePayToken, length must be less than 5000.", new [] { "GooglePayToken" });
            }

            // StoredPaymentMethodId (string) maxLength
            if (this.StoredPaymentMethodId != null && this.StoredPaymentMethodId.Length > 64)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for StoredPaymentMethodId, length must be less than 64.", new [] { "StoredPaymentMethodId" });
            }

            // ThreeDS2SdkVersion (string) maxLength
            if (this.ThreeDS2SdkVersion != null && this.ThreeDS2SdkVersion.Length > 12)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for ThreeDS2SdkVersion, length must be less than 12.", new [] { "ThreeDS2SdkVersion" });
            }

            yield break;
        }
    }

}
