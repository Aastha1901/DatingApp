using System.ComponentModel.DataAnnotations;

namespace API.DTOs
{
    public class RegsiterDto
    {
        [Required]
        public string Username { get; set; }

        [StringLength(8, MinimumLength = 4)]
        [Required]
        public string Password { get; set; }
    }
}