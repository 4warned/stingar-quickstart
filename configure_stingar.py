import os
import sys
import socket
import string
import shutil
import secrets
from getpass import getpass
from urllib.parse import urlparse


def make_color(color, msg):
    bcolors = {
        'HEADER': '\033[95m',
        'OKBLUE': '\033[94m',
        'OKGREEN': '\033[92m',
        'WARNING': '\033[93m',
        'FAIL': '\033[91m',
        'ENDC': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m',
    }
    return bcolors[color] + "%s" % msg + bcolors['ENDC']


def touch(fname, times=None):
    with open(fname, 'a'):
        os.utime(fname, times)


def generate_secret(length=32):
    alphabet = string.ascii_letters + string.digits
    secret = ''.join(secrets.choice(alphabet) for _ in range(length))
    return secret


def generate_stingar_file(output_file, template_file, force_overwrite=True, **kwargs):
    with open(template_file) as env_template_file:
        template = string.Template(env_template_file.read()).safe_substitute(kwargs)

    if not os.path.exists(output_file) or force_overwrite:
        f = open(output_file, 'w')
        f.write(template)
        f.close()
        msg = make_color("OKGREEN", "Wrote file to %s" % output_file)
        print(msg)
    else:
        sys.stderr.write("Not writing file, add -f to override\n")


def test_registry_login(registry, username, password):
    return os.system("docker login -u %s -p %s %s" % (username, password, registry))


def configure_stingar():
    print(make_color(
        "BOLD",
        ("Enter the URL where your STINGAR web app will be available. The "
         "domain must be resolvable. E.g.: sub.domain.tld or localhost/stingar.")))

    domain = None
    url = None
    while not url:
        prompt = make_color("BOLD", "  Domain: ")
        url = input(prompt)
        # if it's a bare fqdn, prepend the proto scheme https so we can use urlparse
        # without a scheme, urlparse puts the full url + path all in netloc attribute of its return object
        # that makes it difficult later to determine if there's a custom path in the url
        if not url.startswith('http'):
            url = 'https://' + url
        url_parsed = urlparse(url)
        try:
            socket.gethostbyname(url_parsed.netloc)
            domain = url_parsed.netloc
        except Exception as e:
            sys.stderr.write(
                make_color("FAIL",
                           "%s is not an active domain name\n" % url_parsed.netloc))
            domain = None
            url = None

    prompt = make_color("BOLD", "Please enter your SSL certificate path:") + make_color("OKBLUE", " [./certs] ")
    cert_path = input(prompt)
    if not cert_path:
        cert_path = "./certs"

    touch('stingar.env')

    # Configure Docker repository information
    docker_repository = "4warned"
    docker_username = ""
    docker_password = ""
    #prompt = make_color("BOLD", "Do you wish to specify an alternate Docker registry? (y/n):") + make_color("OKBLUE",
    #                                                                                                        " [y] ")
    #answer = input(prompt)
    #if not answer:
    #    answer = 'y'
    #set_registry = answer.lower() == ("y" or "yes")
    #if set_registry:
    #    prompt = make_color("BOLD", "Please enter the URL for the Docker registry:") \
    #             + make_color("OKBLUE", " [hub.docker.com] ")
    #    docker_repository = input(prompt)
    #    if not docker_repository:
    #        docker_repository = "4warned"
    #        #docker_repository = "stingarregistry.azurecr.io"
    #    prompt = make_color("BOLD", 'Please enter your Docker registry ') + make_color("UNDERLINE", "username") + ": "
    #    docker_username = input(prompt)
    #    prompt = make_color("BOLD", 'Please enter your Docker registry ') + make_color("UNDERLINE", "password") + ": "
    #    docker_password = getpass(prompt)

    #    print("Testing registry authentication...")
        #if test_registry_login(docker_repository, docker_username, docker_password):
       #     print(make_color("FAIL",
       #                      "Authentication to %s failed." % docker_repository))
       #     exit(-1)
       # print(make_color("OKGREEN",
       #                  "Authentication to %s succeeded." % docker_repository))

    # Configure CIFv3 output options
    cif_enabled = "false"
    cif_host = ""
    cif_token = ""
    cif_provider = ""
    prompt = make_color("BOLD", "Do you wish to enable logging to a remote CIFv3 server? (y/n): ") + \
        make_color("OKBLUE", " [n] ")
    answer = input(prompt)
    enable_cif = answer.lower() == ("y" or "yes")
    if enable_cif:
        cif_enabled = "true"
        prompt = make_color("BOLD", 'Please enter the URL for the remote CIFv3 server: ')
        cif_host = input(prompt)
        prompt = make_color("BOLD", 'Please enter the API token for the remote CIFv3 server: ')
        cif_token = input(prompt)
        prompt = make_color("BOLD", 'Please enter a name you wish to be associated with your organization: ')
        cif_provider = input(prompt)

    print("")
    # Generate stingar.env
    generate_stingar_file(output_file="stingar.env",
                          template_file="templates/stingar.env.template",
                          api_key=generate_secret(),
                          passphrase=generate_secret(),
                          salt=generate_secret(),
                          fluent_key=generate_secret(),
                          cif_enabled=cif_enabled,
                          cif_host=cif_host,
                          cif_token=cif_token,
                          cif_provider=cif_provider,
                          docker_repository=docker_repository,
                          docker_username=docker_username,
                          docker_password=docker_password,
                          ui_hostname=domain,
                          fluentd_hostname=domain
                          )

    # Generate nginx.conf
    generate_stingar_file(output_file="nginx.conf",
                          template_file="templates/nginx.conf.template",
                          ui_hostname=domain)

    #if docker_repository:
    #    docker_repository = docker_repository + "/"
    # Generate docker-compose.yml
    generate_stingar_file(output_file="docker-compose.yml",
                          template_file="templates/docker-compose.yml.template",
                          docker_repository=docker_repository,
                          cert_path=cert_path
                          )
    print("")


def get_docker_path():
    return shutil.which("docker")


def get_docker_compose_path():
    return shutil.which("docker-compose")


def main():

    # Check if docker is installed
    print("")
    print("Checking if 'docker' is installed...")
    docker_path = get_docker_path()
    if not docker_path:
        sys.stderr.write(
            make_color("FAIL",
                       "'docker' not found.\n"))
        exit(-1)
    print("   'docker' found at path '%s'\n" % docker_path)

    # Check if docker-compose is installed
    print("Checking if 'docker-compose' is installed...")
    docker_compose_path = get_docker_compose_path()
    if not docker_compose_path:
        sys.stderr.write(
            make_color("FAIL",
                       "'docker-compose' not found.\n"))
        exit(-1)
    print("   'docker-compose' found at path '%s'\n" % docker_compose_path)

    stingar_env_exists = os.path.exists(
        "stingar.env")

    reconfig = False
    if stingar_env_exists:
        prompt = make_color("BOLD", "Previous stingar.env file detected. Do you wish to reconfigure? (y/n):") + \
                 make_color("OKBLUE", " [y] ")
        answer = input(prompt)
        if not answer:
            answer = 'y'

        reconfig = answer.lower() == ("y" or "yes")

    if reconfig or not stingar_env_exists:
        configure_stingar()
    else:
        print("Will not reconfigure stingar. Terminating.")

    return 0


if __name__ == "__main__":
    main()
