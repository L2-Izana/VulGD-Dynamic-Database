crontab -e

# Not sure this
~/venv/bin/python ~/VulLink/src/pipeline/crawlers/nvd_crawler_dynamic.py --mode yearly --driver_path /usr/local/bin/chromedriver --output_dir ~/datasource/
~/venv/bin/python ~/VulLink/src/pipeline/crawlers/nvd_crawler_dynamic.py --mode recent --driver_path /usr/local/bin/chromedriver --output_dir ~/datasource/