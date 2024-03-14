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
    /// NumberAndBicAccountIdentification
    /// </summary>
    [DataContract(Name = "NumberAndBicAccountIdentification")]
    public partial class NumberAndBicAccountIdentification : IEquatable<NumberAndBicAccountIdentification>, IValidatableObject
    {
        /// <summary>
        /// **numberAndBic**
        /// </summary>
        /// <value>**numberAndBic**</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum NumberAndBic for value: numberAndBic
            /// </summary>
            [EnumMember(Value = "numberAndBic")]
            NumberAndBic = 1

        }


        /// <summary>
        /// **numberAndBic**
        /// </summary>
        /// <value>**numberAndBic**</value>
        [DataMember(Name = "type", IsRequired = false, EmitDefaultValue = false)]
        public TypeEnum Type { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="NumberAndBicAccountIdentification" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected NumberAndBicAccountIdentification() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="NumberAndBicAccountIdentification" /> class.
        /// </summary>
        /// <param name="accountNumber">The bank account number, without separators or whitespace. The length and format depends on the bank or country. (required).</param>
        /// <param name="additionalBankIdentification">additionalBankIdentification.</param>
        /// <param name="bic">The bank&#39;s 8- or 11-character BIC or SWIFT code. (required).</param>
        /// <param name="formFactor">The form factor of the account.  Possible values: **physical**, **virtual**. Default value: **physical**. (default to &quot;physical&quot;).</param>
        /// <param name="type">**numberAndBic** (required) (default to TypeEnum.NumberAndBic).</param>
        public NumberAndBicAccountIdentification(string accountNumber = default(string), AdditionalBankIdentification additionalBankIdentification = default(AdditionalBankIdentification), string bic = default(string), string formFactor = "physical", TypeEnum type = TypeEnum.NumberAndBic)
        {
            this.AccountNumber = accountNumber;
            this.Bic = bic;
            this.Type = type;
            this.AdditionalBankIdentification = additionalBankIdentification;
            // use default value if no "formFactor" provided
            this.FormFactor = formFactor ?? "physical";
        }

        /// <summary>
        /// The bank account number, without separators or whitespace. The length and format depends on the bank or country.
        /// </summary>
        /// <value>The bank account number, without separators or whitespace. The length and format depends on the bank or country.</value>
        [DataMember(Name = "accountNumber", IsRequired = false, EmitDefaultValue = false)]
        public string AccountNumber { get; set; }

        /// <summary>
        /// Gets or Sets AdditionalBankIdentification
        /// </summary>
        [DataMember(Name = "additionalBankIdentification", EmitDefaultValue = false)]
        public AdditionalBankIdentification AdditionalBankIdentification { get; set; }

        /// <summary>
        /// The bank&#39;s 8- or 11-character BIC or SWIFT code.
        /// </summary>
        /// <value>The bank&#39;s 8- or 11-character BIC or SWIFT code.</value>
        [DataMember(Name = "bic", IsRequired = false, EmitDefaultValue = false)]
        public string Bic { get; set; }

        /// <summary>
        /// The form factor of the account.  Possible values: **physical**, **virtual**. Default value: **physical**.
        /// </summary>
        /// <value>The form factor of the account.  Possible values: **physical**, **virtual**. Default value: **physical**.</value>
        [DataMember(Name = "formFactor", EmitDefaultValue = false)]
        public string FormFactor { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class NumberAndBicAccountIdentification {\n");
            sb.Append("  AccountNumber: ").Append(AccountNumber).Append("\n");
            sb.Append("  AdditionalBankIdentification: ").Append(AdditionalBankIdentification).Append("\n");
            sb.Append("  Bic: ").Append(Bic).Append("\n");
            sb.Append("  FormFactor: ").Append(FormFactor).Append("\n");
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
            return this.Equals(input as NumberAndBicAccountIdentification);
        }

        /// <summary>
        /// Returns true if NumberAndBicAccountIdentification instances are equal
        /// </summary>
        /// <param name="input">Instance of NumberAndBicAccountIdentification to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(NumberAndBicAccountIdentification input)
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
                    this.AdditionalBankIdentification == input.AdditionalBankIdentification ||
                    (this.AdditionalBankIdentification != null &&
                    this.AdditionalBankIdentification.Equals(input.AdditionalBankIdentification))
                ) && 
                (
                    this.Bic == input.Bic ||
                    (this.Bic != null &&
                    this.Bic.Equals(input.Bic))
                ) && 
                (
                    this.FormFactor == input.FormFactor ||
                    (this.FormFactor != null &&
                    this.FormFactor.Equals(input.FormFactor))
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
                if (this.AdditionalBankIdentification != null)
                {
                    hashCode = (hashCode * 59) + this.AdditionalBankIdentification.GetHashCode();
                }
                if (this.Bic != null)
                {
                    hashCode = (hashCode * 59) + this.Bic.GetHashCode();
                }
                if (this.FormFactor != null)
                {
                    hashCode = (hashCode * 59) + this.FormFactor.GetHashCode();
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
            if (this.AccountNumber != null && this.AccountNumber.Length > 34)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for AccountNumber, length must be less than 34.", new [] { "AccountNumber" });
            }

            // Bic (string) maxLength
            if (this.Bic != null && this.Bic.Length > 11)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for Bic, length must be less than 11.", new [] { "Bic" });
            }

            // Bic (string) minLength
            if (this.Bic != null && this.Bic.Length < 8)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for Bic, length must be greater than 8.", new [] { "Bic" });
            }

            yield break;
        }
    }

}
