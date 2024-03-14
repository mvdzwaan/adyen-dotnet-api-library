/*
* Transfer webhooks
*
*
* The version of the OpenAPI document: 4
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

namespace Adyen.Model.TransferWebhooks
{
    /// <summary>
    /// UKLocalAccountIdentification
    /// </summary>
    [DataContract(Name = "UKLocalAccountIdentification")]
    public partial class UKLocalAccountIdentification : IEquatable<UKLocalAccountIdentification>, IValidatableObject
    {
        /// <summary>
        /// **ukLocal**
        /// </summary>
        /// <value>**ukLocal**</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum UkLocal for value: ukLocal
            /// </summary>
            [EnumMember(Value = "ukLocal")]
            UkLocal = 1

        }


        /// <summary>
        /// **ukLocal**
        /// </summary>
        /// <value>**ukLocal**</value>
        [DataMember(Name = "type", IsRequired = false, EmitDefaultValue = false)]
        public TypeEnum Type { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="UKLocalAccountIdentification" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected UKLocalAccountIdentification() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="UKLocalAccountIdentification" /> class.
        /// </summary>
        /// <param name="accountNumber">The 8-digit bank account number, without separators or whitespace. (required).</param>
        /// <param name="formFactor">The form factor of the account.  Possible values: **physical**, **virtual**. Default value: **physical**. (default to &quot;physical&quot;).</param>
        /// <param name="sortCode">The 6-digit [sort code](https://en.wikipedia.org/wiki/Sort_code), without separators or whitespace. (required).</param>
        /// <param name="type">**ukLocal** (required) (default to TypeEnum.UkLocal).</param>
        public UKLocalAccountIdentification(string accountNumber = default(string), string formFactor = "physical", string sortCode = default(string), TypeEnum type = TypeEnum.UkLocal)
        {
            this.AccountNumber = accountNumber;
            this.SortCode = sortCode;
            this.Type = type;
            // use default value if no "formFactor" provided
            this.FormFactor = formFactor ?? "physical";
        }

        /// <summary>
        /// The 8-digit bank account number, without separators or whitespace.
        /// </summary>
        /// <value>The 8-digit bank account number, without separators or whitespace.</value>
        [DataMember(Name = "accountNumber", IsRequired = false, EmitDefaultValue = false)]
        public string AccountNumber { get; set; }

        /// <summary>
        /// The form factor of the account.  Possible values: **physical**, **virtual**. Default value: **physical**.
        /// </summary>
        /// <value>The form factor of the account.  Possible values: **physical**, **virtual**. Default value: **physical**.</value>
        [DataMember(Name = "formFactor", EmitDefaultValue = false)]
        public string FormFactor { get; set; }

        /// <summary>
        /// The 6-digit [sort code](https://en.wikipedia.org/wiki/Sort_code), without separators or whitespace.
        /// </summary>
        /// <value>The 6-digit [sort code](https://en.wikipedia.org/wiki/Sort_code), without separators or whitespace.</value>
        [DataMember(Name = "sortCode", IsRequired = false, EmitDefaultValue = false)]
        public string SortCode { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class UKLocalAccountIdentification {\n");
            sb.Append("  AccountNumber: ").Append(AccountNumber).Append("\n");
            sb.Append("  FormFactor: ").Append(FormFactor).Append("\n");
            sb.Append("  SortCode: ").Append(SortCode).Append("\n");
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
            return this.Equals(input as UKLocalAccountIdentification);
        }

        /// <summary>
        /// Returns true if UKLocalAccountIdentification instances are equal
        /// </summary>
        /// <param name="input">Instance of UKLocalAccountIdentification to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(UKLocalAccountIdentification input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AccountNumber == input.AccountNumber ||
                    (this.AccountNumber != null &&
                    this.AccountNumber.Equals(input.AccountNumber))
                ) && 
                (
                    this.FormFactor == input.FormFactor ||
                    (this.FormFactor != null &&
                    this.FormFactor.Equals(input.FormFactor))
                ) && 
                (
                    this.SortCode == input.SortCode ||
                    (this.SortCode != null &&
                    this.SortCode.Equals(input.SortCode))
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
                if (this.AccountNumber != null)
                {
                    hashCode = (hashCode * 59) + this.AccountNumber.GetHashCode();
                }
                if (this.FormFactor != null)
                {
                    hashCode = (hashCode * 59) + this.FormFactor.GetHashCode();
                }
                if (this.SortCode != null)
                {
                    hashCode = (hashCode * 59) + this.SortCode.GetHashCode();
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
            // AccountNumber (string) maxLength
            if (this.AccountNumber != null && this.AccountNumber.Length > 8)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for AccountNumber, length must be less than 8.", new [] { "AccountNumber" });
            }

            // AccountNumber (string) minLength
            if (this.AccountNumber != null && this.AccountNumber.Length < 8)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for AccountNumber, length must be greater than 8.", new [] { "AccountNumber" });
            }

            // SortCode (string) maxLength
            if (this.SortCode != null && this.SortCode.Length > 6)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for SortCode, length must be less than 6.", new [] { "SortCode" });
            }

            // SortCode (string) minLength
            if (this.SortCode != null && this.SortCode.Length < 6)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for SortCode, length must be greater than 6.", new [] { "SortCode" });
            }

            yield break;
        }
    }

}
