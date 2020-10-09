using API.Data;
using System.Collections.Generic;
using System.Threading.Tasks;
using API.Entities;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        public DataContext _Context { get; }
        public ITokenService _Tokenservice { get; }
        public AccountController(DataContext context, ITokenService tokenservice)
        {
            _Tokenservice = tokenservice;
            _Context = context;
        }

        [HttpPost("Register")]
        public async Task<ActionResult<UserDto>> Register(RegsiterDto registerDto)
        {
            if (await UserExists(registerDto.Username)) return BadRequest("UserName is Taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _Context.Users.Add(user);
            await _Context.SaveChangesAsync();

            return new UserDto{
                UserName = user.UserName,
                Token = _Tokenservice.CreateToken(user)
            };
        }

        [HttpPost("Login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _Context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username);

            if (user == null) return Unauthorized("Invalid User!");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }

            return new UserDto{
                UserName = user.UserName,
                Token = _Tokenservice.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string userName)
        {
            return await _Context.Users.AnyAsync(x => x.UserName == userName.ToLower());
        }
    }
}