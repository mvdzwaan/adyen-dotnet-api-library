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
using System.Reflection;

namespace Adyen.Model.BalancePlatform
{
    /// <summary>
    /// TransferRouteRequirementsInner
    /// </summary>
    [JsonConverter(typeof(TransferRouteRequirementsInnerJsonConverter))]
    [DataContract(Name = "TransferRoute_requirements_inner")]
    public partial class TransferRouteRequirementsInner : AbstractOpenAPISchema, IEquatable<TransferRouteRequirementsInner>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TransferRouteRequirementsInner" /> class
        /// with the <see cref="AddressRequirement" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of AddressRequirement.</param>
        public TransferRouteRequirementsInner(AddressRequirement actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "oneOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TransferRouteRequirementsInner" /> class
        /// with the <see cref="AmountMinMaxRequirement" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of AmountMinMaxRequirement.</param>
        public TransferRouteRequirementsInner(AmountMinMaxRequirement actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "oneOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TransferRouteRequirementsInner" /> class
        /// with the <see cref="AmountNonZeroDecimalsRequirement" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of AmountNonZeroDecimalsRequirement.</param>
        public TransferRouteRequirementsInner(AmountNonZeroDecimalsRequirement actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "oneOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TransferRouteRequirementsInner" /> class
        /// with the <see cref="BankAccountIdentificationTypeRequirement" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of BankAccountIdentificationTypeRequirement.</param>
        public TransferRouteRequirementsInner(BankAccountIdentificationTypeRequirement actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "oneOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TransferRouteRequirementsInner" /> class
        /// with the <see cref="IbanAccountIdentificationRequirement" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of IbanAccountIdentificationRequirement.</param>
        public TransferRouteRequirementsInner(IbanAccountIdentificationRequirement actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "oneOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TransferRouteRequirementsInner" /> class
        /// with the <see cref="PaymentInstrumentRequirement" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of PaymentInstrumentRequirement.</param>
        public TransferRouteRequirementsInner(PaymentInstrumentRequirement actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "oneOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TransferRouteRequirementsInner" /> class
        /// with the <see cref="USInternationalAchAddressRequirement" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of USInternationalAchAddressRequirement.</param>
        public TransferRouteRequirementsInner(USInternationalAchAddressRequirement actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "oneOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }


        private Object _actualInstance;

        /// <summary>
        /// Gets or Sets ActualInstance
        /// </summary>
        public override Object ActualInstance
        {
            get
            {
                return _actualInstance;
            }
            set
            {
                if (value.GetType() == typeof(AddressRequirement))
                {
                    this._actualInstance = value;
                }
                else if (value.GetType() == typeof(AmountMinMaxRequirement))
                {
                    this._actualInstance = value;
                }
                else if (value.GetType() == typeof(AmountNonZeroDecimalsRequirement))
                {
                    this._actualInstance = value;
                }
                else if (value.GetType() == typeof(BankAccountIdentificationTypeRequirement))
                {
                    this._actualInstance = value;
                }
                else if (value.GetType() == typeof(IbanAccountIdentificationRequirement))
                {
                    this._actualInstance = value;
                }
                else if (value.GetType() == typeof(PaymentInstrumentRequirement))
                {
                    this._actualInstance = value;
                }
                else if (value.GetType() == typeof(USInternationalAchAddressRequirement))
                {
                    this._actualInstance = value;
                }
                else
                {
                    throw new ArgumentException("Invalid instance found. Must be the following types: AddressRequirement, AmountMinMaxRequirement, AmountNonZeroDecimalsRequirement, BankAccountIdentificationTypeRequirement, IbanAccountIdentificationRequirement, PaymentInstrumentRequirement, USInternationalAchAddressRequirement");
                }
            }
        }

        /// <summary>
        /// Get the actual instance of `AddressRequirement`. If the actual instance is not `AddressRequirement`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of AddressRequirement</returns>
        public AddressRequirement GetAddressRequirement()
        {
            return (AddressRequirement)this.ActualInstance;
        }

        /// <summary>
        /// Get the actual instance of `AmountMinMaxRequirement`. If the actual instance is not `AmountMinMaxRequirement`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of AmountMinMaxRequirement</returns>
        public AmountMinMaxRequirement GetAmountMinMaxRequirement()
        {
            return (AmountMinMaxRequirement)this.ActualInstance;
        }

        /// <summary>
        /// Get the actual instance of `AmountNonZeroDecimalsRequirement`. If the actual instance is not `AmountNonZeroDecimalsRequirement`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of AmountNonZeroDecimalsRequirement</returns>
        public AmountNonZeroDecimalsRequirement GetAmountNonZeroDecimalsRequirement()
        {
            return (AmountNonZeroDecimalsRequirement)this.ActualInstance;
        }

        /// <summary>
        /// Get the actual instance of `BankAccountIdentificationTypeRequirement`. If the actual instance is not `BankAccountIdentificationTypeRequirement`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of BankAccountIdentificationTypeRequirement</returns>
        public BankAccountIdentificationTypeRequirement GetBankAccountIdentificationTypeRequirement()
        {
            return (BankAccountIdentificationTypeRequirement)this.ActualInstance;
        }

        /// <summary>
        /// Get the actual instance of `IbanAccountIdentificationRequirement`. If the actual instance is not `IbanAccountIdentificationRequirement`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of IbanAccountIdentificationRequirement</returns>
        public IbanAccountIdentificationRequirement GetIbanAccountIdentificationRequirement()
        {
            return (IbanAccountIdentificationRequirement)this.ActualInstance;
        }

        /// <summary>
        /// Get the actual instance of `PaymentInstrumentRequirement`. If the actual instance is not `PaymentInstrumentRequirement`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of PaymentInstrumentRequirement</returns>
        public PaymentInstrumentRequirement GetPaymentInstrumentRequirement()
        {
            return (PaymentInstrumentRequirement)this.ActualInstance;
        }

        /// <summary>
        /// Get the actual instance of `USInternationalAchAddressRequirement`. If the actual instance is not `USInternationalAchAddressRequirement`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of USInternationalAchAddressRequirement</returns>
        public USInternationalAchAddressRequirement GetUSInternationalAchAddressRequirement()
        {
            return (USInternationalAchAddressRequirement)this.ActualInstance;
        }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class TransferRouteRequirementsInner {\n");
            sb.Append("  ActualInstance: ").Append(this.ActualInstance).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public override string ToJson()
        {
            return JsonConvert.SerializeObject(this.ActualInstance, TransferRouteRequirementsInner.SerializerSettings);
        }

        /// <summary>
        /// Converts the JSON string into an instance of TransferRouteRequirementsInner
        /// </summary>
        /// <param name="jsonString">JSON string</param>
        /// <returns>An instance of TransferRouteRequirementsInner</returns>
        public static TransferRouteRequirementsInner FromJson(string jsonString)
        {
            TransferRouteRequirementsInner newTransferRouteRequirementsInner = null;

            if (string.IsNullOrEmpty(jsonString))
            {
                return newTransferRouteRequirementsInner;
            }
            int match = 0;
            List<string> matchedTypes = new List<string>();
            JToken typeToken = JObject.Parse(jsonString).GetValue("type");
            string type = typeToken?.Value<string>();
            // Throw exception if jsonString does not contain type param
            if (type == null)
            {
                throw new InvalidDataException("JsonString does not contain required enum type for deserialization.");
            }
            try
            {
                // Check if the jsonString type enum matches the AddressRequirement type enums
                if (ContainsValue<AddressRequirement.TypeEnum>(type))
                {
                    newTransferRouteRequirementsInner = new TransferRouteRequirementsInner(JsonConvert.DeserializeObject<AddressRequirement>(jsonString, TransferRouteRequirementsInner.SerializerSettings));
                    matchedTypes.Add("AddressRequirement");
                    match++;
                }
                // Check if the jsonString type enum matches the AmountMinMaxRequirement type enums
                if (ContainsValue<AmountMinMaxRequirement.TypeEnum>(type))
                {
                    newTransferRouteRequirementsInner = new TransferRouteRequirementsInner(JsonConvert.DeserializeObject<AmountMinMaxRequirement>(jsonString, TransferRouteRequirementsInner.SerializerSettings));
                    matchedTypes.Add("AmountMinMaxRequirement");
                    match++;
                }
                // Check if the jsonString type enum matches the AmountNonZeroDecimalsRequirement type enums
                if (ContainsValue<AmountNonZeroDecimalsRequirement.TypeEnum>(type))
                {
                    newTransferRouteRequirementsInner = new TransferRouteRequirementsInner(JsonConvert.DeserializeObject<AmountNonZeroDecimalsRequirement>(jsonString, TransferRouteRequirementsInner.SerializerSettings));
                    matchedTypes.Add("AmountNonZeroDecimalsRequirement");
                    match++;
                }
                // Check if the jsonString type enum matches the BankAccountIdentificationTypeRequirement type enums
                if (ContainsValue<BankAccountIdentificationTypeRequirement.TypeEnum>(type))
                {
                    newTransferRouteRequirementsInner = new TransferRouteRequirementsInner(JsonConvert.DeserializeObject<BankAccountIdentificationTypeRequirement>(jsonString, TransferRouteRequirementsInner.SerializerSettings));
                    matchedTypes.Add("BankAccountIdentificationTypeRequirement");
                    match++;
                }
                // Check if the jsonString type enum matches the IbanAccountIdentificationRequirement type enums
                if (ContainsValue<IbanAccountIdentificationRequirement.TypeEnum>(type))
                {
                    newTransferRouteRequirementsInner = new TransferRouteRequirementsInner(JsonConvert.DeserializeObject<IbanAccountIdentificationRequirement>(jsonString, TransferRouteRequirementsInner.SerializerSettings));
                    matchedTypes.Add("IbanAccountIdentificationRequirement");
                    match++;
                }
                // Check if the jsonString type enum matches the PaymentInstrumentRequirement type enums
                if (ContainsValue<PaymentInstrumentRequirement.TypeEnum>(type))
                {
                    newTransferRouteRequirementsInner = new TransferRouteRequirementsInner(JsonConvert.DeserializeObject<PaymentInstrumentRequirement>(jsonString, TransferRouteRequirementsInner.SerializerSettings));
                    matchedTypes.Add("PaymentInstrumentRequirement");
                    match++;
                }
                // Check if the jsonString type enum matches the USInternationalAchAddressRequirement type enums
                if (ContainsValue<USInternationalAchAddressRequirement.TypeEnum>(type))
                {
                    newTransferRouteRequirementsInner = new TransferRouteRequirementsInner(JsonConvert.DeserializeObject<USInternationalAchAddressRequirement>(jsonString, TransferRouteRequirementsInner.SerializerSettings));
                    matchedTypes.Add("USInternationalAchAddressRequirement");
                    match++;
                }
            } 
            catch (Exception ex)
            {
                if (!(ex is JsonSerializationException))
                {
                     throw new InvalidDataException(string.Format("Failed to deserialize `{0}` into target: {1}", jsonString, ex.ToString()));
                }
            }

            if (match != 1)
            {
                throw new InvalidDataException("The JSON string `" + jsonString + "` cannot be deserialized into any schema defined. MatchedTypes are: " + matchedTypes);
            }
            
            // deserialization is considered successful at this point if no exception has been thrown.
            return newTransferRouteRequirementsInner;
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as TransferRouteRequirementsInner);
        }

        /// <summary>
        /// Returns true if TransferRouteRequirementsInner instances are equal
        /// </summary>
        /// <param name="input">Instance of TransferRouteRequirementsInner to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(TransferRouteRequirementsInner input)
        {
            if (input == null)
                return false;

            return this.ActualInstance.Equals(input.ActualInstance);
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
                if (this.ActualInstance != null)
                    hashCode = hashCode * 59 + this.ActualInstance.GetHashCode();
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

    /// <summary>
    /// Custom JSON converter for TransferRouteRequirementsInner
    /// </summary>
    public class TransferRouteRequirementsInnerJsonConverter : JsonConverter
    {
        /// <summary>
        /// To write the JSON string
        /// </summary>
        /// <param name="writer">JSON writer</param>
        /// <param name="value">Object to be converted into a JSON string</param>
        /// <param name="serializer">JSON Serializer</param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteRawValue((string)(typeof(TransferRouteRequirementsInner).GetMethod("ToJson").Invoke(value, null)));
        }

        /// <summary>
        /// To convert a JSON string into an object
        /// </summary>
        /// <param name="reader">JSON reader</param>
        /// <param name="objectType">Object type</param>
        /// <param name="existingValue">Existing value</param>
        /// <param name="serializer">JSON Serializer</param>
        /// <returns>The object converted from the JSON string</returns>
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if(reader.TokenType != JsonToken.Null)
            {
                return TransferRouteRequirementsInner.FromJson(JObject.Load(reader).ToString(Formatting.None));
            }
            return null;
        }

        /// <summary>
        /// Check if the object can be converted
        /// </summary>
        /// <param name="objectType">Object type</param>
        /// <returns>True if the object can be converted</returns>
        public override bool CanConvert(Type objectType)
        {
            return false;
        }
    }

}
