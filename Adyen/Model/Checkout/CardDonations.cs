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
    /// CardDonations
    /// </summary>
    [DataContract(Name = "CardDonations")]
    public partial class CardDonations : IEquatable<CardDonations>, IValidatableObject
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
        /// Default payment method details. Common for scheme payment methods, and for simple payment method details.
        /// </summary>
        /// <value>Default payment method details. Common for scheme payment methods, and for simple payment method details.</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum Bcmc for value: bcmc
            /// </summary>
            [EnumMember(Value = "bcmc")]
            Bcmc = 1,

            /// <summary>
            /// Enum Scheme for value: scheme
            /// </summary>
            [EnumMember(Value = "scheme")]
            Scheme = 2,

            /// <summary>
            /// Enum NetworkToken for value: networkToken
            /// </summary>
            [EnumMember(Value = "networkToken")]
            NetworkToken = 3,

            /// <summary>
            /// Enum Giftcard for value: giftcard
            /// </summary>
            [EnumMember(Value = "giftcard")]
            Giftcard = 4,

            /// <summary>
            /// Enum Card for value: card
            /// </summary>
            [EnumMember(Value = "card")]
            Card = 5

        }


        /// <summary>
        /// Default payment method details. Common for scheme payment methods, and for simple payment method details.
        /// </summary>
        /// <value>Default payment method details. Common for scheme payment methods, and for simple payment method details.</value>
        [DataMember(Name = "type", EmitDefaultValue = false)]
        public TypeEnum? Type { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="CardDonations" /> class.
        /// </summary>
        /// <param name="brand">Secondary brand of the card. For example: **plastix**, **hmclub**..</param>
        /// <param name="checkoutAttemptId">The checkout attempt identifier..</param>
        /// <param name="cupsecureplusSmscode">cupsecureplusSmscode.</param>
        /// <param name="cvc">The card verification code. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide)..</param>
        /// <param name="encryptedCardNumber">The encrypted card number..</param>
        /// <param name="encryptedExpiryMonth">The encrypted card expiry month..</param>
        /// <param name="encryptedExpiryYear">The encrypted card expiry year..</param>
        /// <param name="encryptedSecurityCode">The encrypted card verification code..</param>
        /// <param name="expiryMonth">The card expiry month. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide)..</param>
        /// <param name="expiryYear">The card expiry year. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide)..</param>
        /// <param name="fundingSource">The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**..</param>
        /// <param name="holderName">The name of the card holder..</param>
        /// <param name="networkPaymentReference">The transaction identifier from card schemes. This is the [&#x60;networkTxReference&#x60;](https://docs.adyen.com/api-explorer/#/CheckoutService/latest/post/payments__resParam_additionalData-ResponseAdditionalDataCommon-networkTxReference) from the response to the first payment..</param>
        /// <param name="number">The card number. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide)..</param>
        /// <param name="recurringDetailReference">This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token..</param>
        /// <param name="shopperNotificationReference">The &#x60;shopperNotificationReference&#x60; returned in the response when you requested to notify the shopper. Used only for recurring payments in India..</param>
        /// <param name="srcCorrelationId">An identifier used for the Click to Pay transaction..</param>
        /// <param name="srcDigitalCardId">The SRC reference for the Click to Pay token..</param>
        /// <param name="srcScheme">The scheme that is being used for Click to Pay..</param>
        /// <param name="srcTokenReference">The reference for the Click to Pay token..</param>
        /// <param name="storedPaymentMethodId">This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token..</param>
        /// <param name="threeDS2SdkVersion">Required for mobile integrations. Version of the 3D Secure 2 mobile SDK..</param>
        /// <param name="type">Default payment method details. Common for scheme payment methods, and for simple payment method details. (default to TypeEnum.Scheme).</param>
        public CardDonations(string brand = default(string), string checkoutAttemptId = default(string), string cupsecureplusSmscode = default(string), string cvc = default(string), string encryptedCardNumber = default(string), string encryptedExpiryMonth = default(string), string encryptedExpiryYear = default(string), string encryptedSecurityCode = default(string), string expiryMonth = default(string), string expiryYear = default(string), FundingSourceEnum? fundingSource = default(FundingSourceEnum?), string holderName = default(string), string networkPaymentReference = default(string), string number = default(string), string recurringDetailReference = default(string), string shopperNotificationReference = default(string), string srcCorrelationId = default(string), string srcDigitalCardId = default(string), string srcScheme = default(string), string srcTokenReference = default(string), string storedPaymentMethodId = default(string), string threeDS2SdkVersion = default(string), TypeEnum? type = TypeEnum.Scheme)
        {
            this.Brand = brand;
            this.CheckoutAttemptId = checkoutAttemptId;
            this.CupsecureplusSmscode = cupsecureplusSmscode;
            this.Cvc = cvc;
            this.EncryptedCardNumber = encryptedCardNumber;
            this.EncryptedExpiryMonth = encryptedExpiryMonth;
            this.EncryptedExpiryYear = encryptedExpiryYear;
            this.EncryptedSecurityCode = encryptedSecurityCode;
            this.ExpiryMonth = expiryMonth;
            this.ExpiryYear = expiryYear;
            this.FundingSource = fundingSource;
            this.HolderName = holderName;
            this.NetworkPaymentReference = networkPaymentReference;
            this.Number = number;
            this.RecurringDetailReference = recurringDetailReference;
            this.ShopperNotificationReference = shopperNotificationReference;
            this.SrcCorrelationId = srcCorrelationId;
            this.SrcDigitalCardId = srcDigitalCardId;
            this.SrcScheme = srcScheme;
            this.SrcTokenReference = srcTokenReference;
            this.StoredPaymentMethodId = storedPaymentMethodId;
            this.ThreeDS2SdkVersion = threeDS2SdkVersion;
            this.Type = type;
        }

        /// <summary>
        /// Secondary brand of the card. For example: **plastix**, **hmclub**.
        /// </summary>
        /// <value>Secondary brand of the card. For example: **plastix**, **hmclub**.</value>
        [DataMember(Name = "brand", EmitDefaultValue = false)]
        public string Brand { get; set; }

        /// <summary>
        /// The checkout attempt identifier.
        /// </summary>
        /// <value>The checkout attempt identifier.</value>
        [DataMember(Name = "checkoutAttemptId", EmitDefaultValue = false)]
        public string CheckoutAttemptId { get; set; }

        /// <summary>
        /// Gets or Sets CupsecureplusSmscode
        /// </summary>
        [DataMember(Name = "cupsecureplus.smscode", EmitDefaultValue = false)]
        [Obsolete]
        public string CupsecureplusSmscode { get; set; }

        /// <summary>
        /// The card verification code. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).
        /// </summary>
        /// <value>The card verification code. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).</value>
        [DataMember(Name = "cvc", EmitDefaultValue = false)]
        public string Cvc { get; set; }

        /// <summary>
        /// The encrypted card number.
        /// </summary>
        /// <value>The encrypted card number.</value>
        [DataMember(Name = "encryptedCardNumber", EmitDefaultValue = false)]
        public string EncryptedCardNumber { get; set; }

        /// <summary>
        /// The encrypted card expiry month.
        /// </summary>
        /// <value>The encrypted card expiry month.</value>
        [DataMember(Name = "encryptedExpiryMonth", EmitDefaultValue = false)]
        public string EncryptedExpiryMonth { get; set; }

        /// <summary>
        /// The encrypted card expiry year.
        /// </summary>
        /// <value>The encrypted card expiry year.</value>
        [DataMember(Name = "encryptedExpiryYear", EmitDefaultValue = false)]
        public string EncryptedExpiryYear { get; set; }

        /// <summary>
        /// The encrypted card verification code.
        /// </summary>
        /// <value>The encrypted card verification code.</value>
        [DataMember(Name = "encryptedSecurityCode", EmitDefaultValue = false)]
        public string EncryptedSecurityCode { get; set; }

        /// <summary>
        /// The card expiry month. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).
        /// </summary>
        /// <value>The card expiry month. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).</value>
        [DataMember(Name = "expiryMonth", EmitDefaultValue = false)]
        public string ExpiryMonth { get; set; }

        /// <summary>
        /// The card expiry year. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).
        /// </summary>
        /// <value>The card expiry year. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).</value>
        [DataMember(Name = "expiryYear", EmitDefaultValue = false)]
        public string ExpiryYear { get; set; }

        /// <summary>
        /// The name of the card holder.
        /// </summary>
        /// <value>The name of the card holder.</value>
        [DataMember(Name = "holderName", EmitDefaultValue = false)]
        public string HolderName { get; set; }

        /// <summary>
        /// The transaction identifier from card schemes. This is the [&#x60;networkTxReference&#x60;](https://docs.adyen.com/api-explorer/#/CheckoutService/latest/post/payments__resParam_additionalData-ResponseAdditionalDataCommon-networkTxReference) from the response to the first payment.
        /// </summary>
        /// <value>The transaction identifier from card schemes. This is the [&#x60;networkTxReference&#x60;](https://docs.adyen.com/api-explorer/#/CheckoutService/latest/post/payments__resParam_additionalData-ResponseAdditionalDataCommon-networkTxReference) from the response to the first payment.</value>
        [DataMember(Name = "networkPaymentReference", EmitDefaultValue = false)]
        public string NetworkPaymentReference { get; set; }

        /// <summary>
        /// The card number. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).
        /// </summary>
        /// <value>The card number. Only collect raw card data if you are [fully PCI compliant](https://docs.adyen.com/development-resources/pci-dss-compliance-guide).</value>
        [DataMember(Name = "number", EmitDefaultValue = false)]
        public string Number { get; set; }

        /// <summary>
        /// This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.
        /// </summary>
        /// <value>This is the &#x60;recurringDetailReference&#x60; returned in the response when you created the token.</value>
        [DataMember(Name = "recurringDetailReference", EmitDefaultValue = false)]
        [Obsolete]
        public string RecurringDetailReference { get; set; }

        /// <summary>
        /// The &#x60;shopperNotificationReference&#x60; returned in the response when you requested to notify the shopper. Used only for recurring payments in India.
        /// </summary>
        /// <value>The &#x60;shopperNotificationReference&#x60; returned in the response when you requested to notify the shopper. Used only for recurring payments in India.</value>
        [DataMember(Name = "shopperNotificationReference", EmitDefaultValue = false)]
        public string ShopperNotificationReference { get; set; }

        /// <summary>
        /// An identifier used for the Click to Pay transaction.
        /// </summary>
        /// <value>An identifier used for the Click to Pay transaction.</value>
        [DataMember(Name = "srcCorrelationId", EmitDefaultValue = false)]
        public string SrcCorrelationId { get; set; }

        /// <summary>
        /// The SRC reference for the Click to Pay token.
        /// </summary>
        /// <value>The SRC reference for the Click to Pay token.</value>
        [DataMember(Name = "srcDigitalCardId", EmitDefaultValue = false)]
        public string SrcDigitalCardId { get; set; }

        /// <summary>
        /// The scheme that is being used for Click to Pay.
        /// </summary>
        /// <value>The scheme that is being used for Click to Pay.</value>
        [DataMember(Name = "srcScheme", EmitDefaultValue = false)]
        public string SrcScheme { get; set; }

        /// <summary>
        /// The reference for the Click to Pay token.
        /// </summary>
        /// <value>The reference for the Click to Pay token.</value>
        [DataMember(Name = "srcTokenReference", EmitDefaultValue = false)]
        public string SrcTokenReference { get; set; }

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
            sb.Append("class CardDonations {\n");
            sb.Append("  Brand: ").Append(Brand).Append("\n");
            sb.Append("  CheckoutAttemptId: ").Append(CheckoutAttemptId).Append("\n");
            sb.Append("  CupsecureplusSmscode: ").Append(CupsecureplusSmscode).Append("\n");
            sb.Append("  Cvc: ").Append(Cvc).Append("\n");
            sb.Append("  EncryptedCardNumber: ").Append(EncryptedCardNumber).Append("\n");
            sb.Append("  EncryptedExpiryMonth: ").Append(EncryptedExpiryMonth).Append("\n");
            sb.Append("  EncryptedExpiryYear: ").Append(EncryptedExpiryYear).Append("\n");
            sb.Append("  EncryptedSecurityCode: ").Append(EncryptedSecurityCode).Append("\n");
            sb.Append("  ExpiryMonth: ").Append(ExpiryMonth).Append("\n");
            sb.Append("  ExpiryYear: ").Append(ExpiryYear).Append("\n");
            sb.Append("  FundingSource: ").Append(FundingSource).Append("\n");
            sb.Append("  HolderName: ").Append(HolderName).Append("\n");
            sb.Append("  NetworkPaymentReference: ").Append(NetworkPaymentReference).Append("\n");
            sb.Append("  Number: ").Append(Number).Append("\n");
            sb.Append("  RecurringDetailReference: ").Append(RecurringDetailReference).Append("\n");
            sb.Append("  ShopperNotificationReference: ").Append(ShopperNotificationReference).Append("\n");
            sb.Append("  SrcCorrelationId: ").Append(SrcCorrelationId).Append("\n");
            sb.Append("  SrcDigitalCardId: ").Append(SrcDigitalCardId).Append("\n");
            sb.Append("  SrcScheme: ").Append(SrcScheme).Append("\n");
            sb.Append("  SrcTokenReference: ").Append(SrcTokenReference).Append("\n");
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
            return this.Equals(input as CardDonations);
        }

        /// <summary>
        /// Returns true if CardDonations instances are equal
        /// </summary>
        /// <param name="input">Instance of CardDonations to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CardDonations input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Brand == input.Brand ||
                    (this.Brand != null &&
                    this.Brand.Equals(input.Brand))
                ) && 
                (
                    this.CheckoutAttemptId == input.CheckoutAttemptId ||
                    (this.CheckoutAttemptId != null &&
                    this.CheckoutAttemptId.Equals(input.CheckoutAttemptId))
                ) && 
                (
                    this.CupsecureplusSmscode == input.CupsecureplusSmscode ||
                    (this.CupsecureplusSmscode != null &&
                    this.CupsecureplusSmscode.Equals(input.CupsecureplusSmscode))
                ) && 
                (
                    this.Cvc == input.Cvc ||
                    (this.Cvc != null &&
                    this.Cvc.Equals(input.Cvc))
                ) && 
                (
                    this.EncryptedCardNumber == input.EncryptedCardNumber ||
                    (this.EncryptedCardNumber != null &&
                    this.EncryptedCardNumber.Equals(input.EncryptedCardNumber))
                ) && 
                (
                    this.EncryptedExpiryMonth == input.EncryptedExpiryMonth ||
                    (this.EncryptedExpiryMonth != null &&
                    this.EncryptedExpiryMonth.Equals(input.EncryptedExpiryMonth))
                ) && 
                (
                    this.EncryptedExpiryYear == input.EncryptedExpiryYear ||
                    (this.EncryptedExpiryYear != null &&
                    this.EncryptedExpiryYear.Equals(input.EncryptedExpiryYear))
                ) && 
                (
                    this.EncryptedSecurityCode == input.EncryptedSecurityCode ||
                    (this.EncryptedSecurityCode != null &&
                    this.EncryptedSecurityCode.Equals(input.EncryptedSecurityCode))
                ) && 
                (
                    this.ExpiryMonth == input.ExpiryMonth ||
                    (this.ExpiryMonth != null &&
                    this.ExpiryMonth.Equals(input.ExpiryMonth))
                ) && 
                (
                    this.ExpiryYear == input.ExpiryYear ||
                    (this.ExpiryYear != null &&
                    this.ExpiryYear.Equals(input.ExpiryYear))
                ) && 
                (
                    this.FundingSource == input.FundingSource ||
                    this.FundingSource.Equals(input.FundingSource)
                ) && 
                (
                    this.HolderName == input.HolderName ||
                    (this.HolderName != null &&
                    this.HolderName.Equals(input.HolderName))
                ) && 
                (
                    this.NetworkPaymentReference == input.NetworkPaymentReference ||
                    (this.NetworkPaymentReference != null &&
                    this.NetworkPaymentReference.Equals(input.NetworkPaymentReference))
                ) && 
                (
                    this.Number == input.Number ||
                    (this.Number != null &&
                    this.Number.Equals(input.Number))
                ) && 
                (
                    this.RecurringDetailReference == input.RecurringDetailReference ||
                    (this.RecurringDetailReference != null &&
                    this.RecurringDetailReference.Equals(input.RecurringDetailReference))
                ) && 
                (
                    this.ShopperNotificationReference == input.ShopperNotificationReference ||
                    (this.ShopperNotificationReference != null &&
                    this.ShopperNotificationReference.Equals(input.ShopperNotificationReference))
                ) && 
                (
                    this.SrcCorrelationId == input.SrcCorrelationId ||
                    (this.SrcCorrelationId != null &&
                    this.SrcCorrelationId.Equals(input.SrcCorrelationId))
                ) && 
                (
                    this.SrcDigitalCardId == input.SrcDigitalCardId ||
                    (this.SrcDigitalCardId != null &&
                    this.SrcDigitalCardId.Equals(input.SrcDigitalCardId))
                ) && 
                (
                    this.SrcScheme == input.SrcScheme ||
                    (this.SrcScheme != null &&
                    this.SrcScheme.Equals(input.SrcScheme))
                ) && 
                (
                    this.SrcTokenReference == input.SrcTokenReference ||
                    (this.SrcTokenReference != null &&
                    this.SrcTokenReference.Equals(input.SrcTokenReference))
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
                if (this.Brand != null)
                {
                    hashCode = (hashCode * 59) + this.Brand.GetHashCode();
                }
                if (this.CheckoutAttemptId != null)
                {
                    hashCode = (hashCode * 59) + this.CheckoutAttemptId.GetHashCode();
                }
                if (this.CupsecureplusSmscode != null)
                {
                    hashCode = (hashCode * 59) + this.CupsecureplusSmscode.GetHashCode();
                }
                if (this.Cvc != null)
                {
                    hashCode = (hashCode * 59) + this.Cvc.GetHashCode();
                }
                if (this.EncryptedCardNumber != null)
                {
                    hashCode = (hashCode * 59) + this.EncryptedCardNumber.GetHashCode();
                }
                if (this.EncryptedExpiryMonth != null)
                {
                    hashCode = (hashCode * 59) + this.EncryptedExpiryMonth.GetHashCode();
                }
                if (this.EncryptedExpiryYear != null)
                {
                    hashCode = (hashCode * 59) + this.EncryptedExpiryYear.GetHashCode();
                }
                if (this.EncryptedSecurityCode != null)
                {
                    hashCode = (hashCode * 59) + this.EncryptedSecurityCode.GetHashCode();
                }
                if (this.ExpiryMonth != null)
                {
                    hashCode = (hashCode * 59) + this.ExpiryMonth.GetHashCode();
                }
                if (this.ExpiryYear != null)
                {
                    hashCode = (hashCode * 59) + this.ExpiryYear.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.FundingSource.GetHashCode();
                if (this.HolderName != null)
                {
                    hashCode = (hashCode * 59) + this.HolderName.GetHashCode();
                }
                if (this.NetworkPaymentReference != null)
                {
                    hashCode = (hashCode * 59) + this.NetworkPaymentReference.GetHashCode();
                }
                if (this.Number != null)
                {
                    hashCode = (hashCode * 59) + this.Number.GetHashCode();
                }
                if (this.RecurringDetailReference != null)
                {
                    hashCode = (hashCode * 59) + this.RecurringDetailReference.GetHashCode();
                }
                if (this.ShopperNotificationReference != null)
                {
                    hashCode = (hashCode * 59) + this.ShopperNotificationReference.GetHashCode();
                }
                if (this.SrcCorrelationId != null)
                {
                    hashCode = (hashCode * 59) + this.SrcCorrelationId.GetHashCode();
                }
                if (this.SrcDigitalCardId != null)
                {
                    hashCode = (hashCode * 59) + this.SrcDigitalCardId.GetHashCode();
                }
                if (this.SrcScheme != null)
                {
                    hashCode = (hashCode * 59) + this.SrcScheme.GetHashCode();
                }
                if (this.SrcTokenReference != null)
                {
                    hashCode = (hashCode * 59) + this.SrcTokenReference.GetHashCode();
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
            // EncryptedCardNumber (string) maxLength
            if (this.EncryptedCardNumber != null && this.EncryptedCardNumber.Length > 15000)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for EncryptedCardNumber, length must be less than 15000.", new [] { "EncryptedCardNumber" });
            }

            // EncryptedExpiryMonth (string) maxLength
            if (this.EncryptedExpiryMonth != null && this.EncryptedExpiryMonth.Length > 15000)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for EncryptedExpiryMonth, length must be less than 15000.", new [] { "EncryptedExpiryMonth" });
            }

            // EncryptedExpiryYear (string) maxLength
            if (this.EncryptedExpiryYear != null && this.EncryptedExpiryYear.Length > 15000)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for EncryptedExpiryYear, length must be less than 15000.", new [] { "EncryptedExpiryYear" });
            }

            // EncryptedSecurityCode (string) maxLength
            if (this.EncryptedSecurityCode != null && this.EncryptedSecurityCode.Length > 15000)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for EncryptedSecurityCode, length must be less than 15000.", new [] { "EncryptedSecurityCode" });
            }

            // HolderName (string) maxLength
            if (this.HolderName != null && this.HolderName.Length > 15000)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for HolderName, length must be less than 15000.", new [] { "HolderName" });
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
