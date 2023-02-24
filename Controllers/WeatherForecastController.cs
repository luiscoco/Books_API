using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace BookStoreApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("~/GetWeatherForecastWithNoPermissions")]
        public IEnumerable<WeatherForecast> GetWeatherForecastWithNoPermissions()
        {
            _logger.LogInformation("Weather forecast Get method called");
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        //Roles: Admin
        [HttpGet]
        [Authorize(Roles = "Admin")]
        [Route("~/GetWeatherForecastAdmin")]
        public IEnumerable<WeatherForecast> GetWeatherForecastAdmin()
        {
            _logger.LogInformation("Weather forecast Get method called");
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        //Roles: User
        [HttpGet]
        [Authorize(Roles = "User")]
        [Route("~/GetWeatherForecastUser")]
        public IEnumerable<WeatherForecast> GetWeatherForecastUser()
        {
            _logger.LogInformation("Weather forecast Get method called");
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}