namespace AESManaged.Models
{
    public class ApiTokenModel
    {
        public string Salt { get; set; }
        public string Cypher { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}
