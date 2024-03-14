/*
* Configuration API
*
*
* The version of the OpenAPI document: 2
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

namespace Adyen.Model.BalancePlatform
{
    /// <summary>
    /// AULocalAccountIdentification
    /// </summary>
    [DataContract(Name = "AULocalAccountIdentification")]
    public partial class AULocalAccountIdentification : IEquatable<AULocalAccountIdentification>, IValidatableObject
    {
        /// <summary>
        /// **auLocal**
        /// </summary>
        /// <value>**auLocal**</value>
        [JsonConverter(typeof(StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum AuLocal for value: auLocal
            /// </summary>
            [EnumMember(Value = "auLocal")]
            AuLocal = 1

        }


        /// <summary>
        /// **auLocal**
        /// </summary>
        /// <value>**auLocal**</value>
        [DataMember(Name = "type", IsRequired = false, EmitDefaultValue = false)]
        public TypeEnum Type { get; set; }
        /// <summary>
        /// Initializes a new instance of the <see cref="AULocalAccountIdentification" /> class.
        /// </summary>
        [JsonConstructorAttribute]
        protected AULocalAccountIdentification() { }
        /// <summary>
        /// Initializes a new instance of the <see cref="AULocalAccountIdentification" /> class.
        /// </summary>
        /// <param name="accountNumber">The bank account number, without separators or whitespace. (required).</param>
        /// <param name="bsbCode">The 6-digit [Bank State Branch (BSB) code](https://en.wikipedia.org/wiki/Bank_state_branch), without separators or whitespace. (required).</param>
        /// <param name="formFactor">The form factor of the account.  Possible values: **physical**, **virtual**. Default value: **physical**. (default to &quot;physical&quot;).</param>
        /// <param name="type">**auLocal** (required) (default to TypeEnum.AuLocal).</param>
        public AULocalAccountIdentification(string accountNumber = default(string), string bsbCode = default(string), string formFactor = "physical", TypeEnum type = TypeEnum.AuLocal)
        {
            this.AccountNumber = accountNumber;
            this.BsbCode = bsbCode;
            this.Type = type;
            // use default value if no "formFactor" provided
            this.FormFactor = formFactor ?? "physical";
        }

        /// <summary>
        /// The bank account number, without separators or whitespace.
        /// </summary>
        /// <value>The bank account number, without separators or whitespace.</value>
        [DataMember(Name = "accountNumber", IsRequired = false, EmitDefaultValue = false)]
        public string AccountNumber { get; set; }

        /// <summary>
        /// The 6-digit [Bank State Branch (BSB) code](https://en.wikipedia.org/wiki/Bank_state_branch), without separators or whitespace.
        /// </summary>
        /// <value>The 6-digit [Bank State Branch (BSB) code](https://en.wikipedia.org/wiki/Bank_state_branch), without separators or whitespace.</value>
        [DataMember(Name = "bsbCode", IsRequired = false, EmitDefaultValue = false)]
        public string BsbCode { get; set; }

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
            sb.Append("class AULocalAccountIdentification {\n");
            sb.Append("  AccountNumber: ").Append(AccountNumber).Append("\n");
            sb.Append("  BsbCode: ").Append(BsbCode).Append("\n");
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
            return this.Equals(input as AULocalAccountIdentification);
        }

        /// <summary>
        /// Returns true if AULocalAccountIdentification instances are equal
        /// </summary>
        /// <param name="input">Instance of AULocalAccountIdentification to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AULocalAccountIdentification input)
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
                    this.BsbCode == input.BsbCode ||
                    (this.BsbCode != null &&
                    this.BsbCode.Equals(input.BsbCode))
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
                if (this.BsbCode != null)
                {
                    hashCode = (hashCode * 59) + this.BsbCode.GetHashCode();
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
            if (this.AccountNumber != null && this.AccountNumber.Length > 9)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for AccountNumber, length must be less than 9.", new [] { "AccountNumber" });
            }

            // AccountNumber (string) minLength
            if (this.AccountNumber != null && this.AccountNumber.Length < 5)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for AccountNumber, length must be greater than 5.", new [] { "AccountNumber" });
            }

            // BsbCode (string) maxLength
            if (this.BsbCode != null && this.BsbCode.Length > 6)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for BsbCode, length must be less than 6.", new [] { "BsbCode" });
            }

            // BsbCode (string) minLength
            if (this.BsbCode != null && this.BsbCode.Length < 6)
            {
                yield return new System.ComponentModel.DataAnnotations.ValidationResult("Invalid value for BsbCode, length must be greater than 6.", new [] { "BsbCode" });
            }

            yield break;
        }
    }

}
