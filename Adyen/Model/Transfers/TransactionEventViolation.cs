/*
* Transfers API
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

namespace Adyen.Model.Transfers
{
    /// <summary>
    /// TransactionEventViolation
    /// </summary>
    [DataContract(Name = "TransactionEventViolation")]
    public partial class TransactionEventViolation : IEquatable<TransactionEventViolation>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TransactionEventViolation" /> class.
        /// </summary>
        /// <param name="reason">An explanation about why the transaction rule failed..</param>
        /// <param name="transactionRule">transactionRule.</param>
        /// <param name="transactionRuleSource">transactionRuleSource.</param>
        public TransactionEventViolation(string reason = default(string), TransactionRuleReference transactionRule = default(TransactionRuleReference), TransactionRuleSource transactionRuleSource = default(TransactionRuleSource))
        {
            this.Reason = reason;
            this.TransactionRule = transactionRule;
            this.TransactionRuleSource = transactionRuleSource;
        }

        /// <summary>
        /// An explanation about why the transaction rule failed.
        /// </summary>
        /// <value>An explanation about why the transaction rule failed.</value>
        [DataMember(Name = "reason", EmitDefaultValue = false)]
        public string Reason { get; set; }

        /// <summary>
        /// Gets or Sets TransactionRule
        /// </summary>
        [DataMember(Name = "transactionRule", EmitDefaultValue = false)]
        public TransactionRuleReference TransactionRule { get; set; }

        /// <summary>
        /// Gets or Sets TransactionRuleSource
        /// </summary>
        [DataMember(Name = "transactionRuleSource", EmitDefaultValue = false)]
        public TransactionRuleSource TransactionRuleSource { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class TransactionEventViolation {\n");
            sb.Append("  Reason: ").Append(Reason).Append("\n");
            sb.Append("  TransactionRule: ").Append(TransactionRule).Append("\n");
            sb.Append("  TransactionRuleSource: ").Append(TransactionRuleSource).Append("\n");
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
            return this.Equals(input as TransactionEventViolation);
        }

        /// <summary>
        /// Returns true if TransactionEventViolation instances are equal
        /// </summary>
        /// <param name="input">Instance of TransactionEventViolation to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TransactionEventViolation input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Reason == input.Reason ||
                    (this.Reason != null &&
                    this.Reason.Equals(input.Reason))
                ) && 
                (
                    this.TransactionRule == input.TransactionRule ||
                    (this.TransactionRule != null &&
                    this.TransactionRule.Equals(input.TransactionRule))
                ) && 
                (
                    this.TransactionRuleSource == input.TransactionRuleSource ||
                    (this.TransactionRuleSource != null &&
                    this.TransactionRuleSource.Equals(input.TransactionRuleSource))
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
                if (this.Reason != null)
                {
                    hashCode = (hashCode * 59) + this.Reason.GetHashCode();
                }
                if (this.TransactionRule != null)
                {
                    hashCode = (hashCode * 59) + this.TransactionRule.GetHashCode();
                }
                if (this.TransactionRuleSource != null)
                {
                    hashCode = (hashCode * 59) + this.TransactionRuleSource.GetHashCode();
                }
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
            yield break;
        }
    }

}
