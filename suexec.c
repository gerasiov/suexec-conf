/* This is forked version of suexec helper from apache2 distribution.
 *
 * Copyright 2009 (c) Apache Software Foundation
 * Copyright 2011 (c) Alexander GQ Gerasiov <gq@debian.org>
 *
 * This file is licensed under Apache License, Version 2.0. You may obtain a
 * copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * suexec.c -- "Wrapper" support program for suEXEC behaviour for Apache
 *
 */

#include "suexec.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <pwd.h>
#include <grp.h>

#include <confuse.h>

#if defined(PATH_MAX)
#define AP_MAXPATH PATH_MAX
#elif defined(MAXPATHLEN)
#define AP_MAXPATH MAXPATHLEN
#else
#define AP_MAXPATH 8192
#endif

#define AP_ENVBUF 256

extern char **environ;
static FILE *log = NULL;

static cfg_t *cfg = 0;

static const char * config_file = AP_SUEXEC_CONF;
cfg_opt_t config_opts[] =
{
        CFG_STR("logfile", AP_LOG_EXEC, CFGF_NONE),
        CFG_STR_LIST("always_allow", "", CFGF_NONE),
        CFG_INT("min_uid", AP_UID_MIN, CFGF_NONE),
        CFG_INT("min_gid", AP_GID_MIN, CFGF_NONE),
        CFG_STR("httpd_user", AP_HTTPD_USER, CFGF_NONE),
        CFG_STR("doc_root", AP_DOC_ROOT, CFGF_NONE),
        CFG_STR("userdir_suffix", AP_USERDIR_SUFFIX, CFGF_NONE),
        CFG_INT("umask", AP_SUEXEC_UMASK, CFGF_NONE),
        CFG_END()
};

static const char *const safe_env_lst[] =
{
    /* variable name starts with */
    "HTTP_",
    "SSL_",
    "PHP_",

    /* variable name is */
    "AUTH_TYPE=",
    "CONTENT_LENGTH=",
    "CONTENT_TYPE=",
    "DATE_GMT=",
    "DATE_LOCAL=",
    "DOCUMENT_NAME=",
    "DOCUMENT_PATH_INFO=",
    "DOCUMENT_ROOT=",
    "DOCUMENT_URI=",
    "GATEWAY_INTERFACE=",
    "HTTPS=",
    "LAST_MODIFIED=",
    "PATH_INFO=",
    "PATH_TRANSLATED=",
    "QUERY_STRING=",
    "QUERY_STRING_UNESCAPED=",
    "REMOTE_ADDR=",
    "REMOTE_HOST=",
    "REMOTE_IDENT=",
    "REMOTE_PORT=",
    "REMOTE_USER=",
    "REDIRECT_HANDLER=",
    "REDIRECT_QUERY_STRING=",
    "REDIRECT_REMOTE_USER=",
    "REDIRECT_STATUS=",
    "REDIRECT_URL=",
    "REQUEST_METHOD=",
    "REQUEST_URI=",
    "SCRIPT_FILENAME=",
    "SCRIPT_NAME=",
    "SCRIPT_URI=",
    "SCRIPT_URL=",
    "SERVER_ADMIN=",
    "SERVER_NAME=",
    "SERVER_ADDR=",
    "SERVER_PORT=",
    "SERVER_PROTOCOL=",
    "SERVER_SIGNATURE=",
    "SERVER_SOFTWARE=",
    "UNIQUE_ID=",
    "USER_NAME=",
    "TZ=",
    NULL
};


static void err_output(int is_error, const char *fmt, va_list ap)
{
    time_t timevar;
    struct tm *lt;

    if (!log) {
        if ((log = fopen(cfg_getstr(cfg, "logfile"), "a")) == NULL) {
            fprintf(stderr, "suexec failure: could not open log file\n");
            perror("fopen");
            exit(1);
        }
    }

    if (is_error) {
        fprintf(stderr, "suexec policy violation: see suexec log for more "
                        "details\n");
    }

    time(&timevar);
    lt = localtime(&timevar);

    fprintf(log, "[%d-%.2d-%.2d %.2d:%.2d:%.2d]: ",
            lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
            lt->tm_hour, lt->tm_min, lt->tm_sec);

    vfprintf(log, fmt, ap);

    fflush(log);
    return;
}

static void log_err(const char *fmt,...)
{
    va_list ap;

    va_start(ap, fmt);
    err_output(1, fmt, ap); /* 1 == is_error */
    va_end(ap);
    return;
}

static void log_no_err(const char *fmt,...)
{
    va_list ap;

    va_start(ap, fmt);
    err_output(0, fmt, ap); /* 0 == !is_error */
    va_end(ap);
    return;
}

static void clean_env(void)
{
    char pathbuf[512];
    char **cleanenv;
    char **ep;
    int cidx = 0;
    int idx;

    /* While cleaning the environment, the environment should be clean.
     * (e.g. malloc() may get the name of a file for writing debugging info.
     * Bad news if MALLOC_DEBUG_FILE is set to /etc/passwd.  Sprintf() may be
     * susceptible to bad locale settings....)
     * (from PR 2790)
     */
    char **envp = environ;
    char *empty_ptr = NULL;

    environ = &empty_ptr; /* VERY safe environment */

    if ((cleanenv = (char **) calloc(AP_ENVBUF, sizeof(char *))) == NULL) {
        fprintf(stderr, "fatal: suexec failed to malloc memory for environment\n");
        exit(120);
    }

    sprintf(pathbuf, "PATH=%s", AP_SAFE_PATH);
    cleanenv[cidx] = strdup(pathbuf);
    cidx++;

    for (ep = envp; *ep && cidx < AP_ENVBUF-1; ep++) {
        for (idx = 0; safe_env_lst[idx]; idx++) {
            if (!strncmp(*ep, safe_env_lst[idx],
                         strlen(safe_env_lst[idx]))) {
                cleanenv[cidx] = *ep;
                cidx++;
                break;
            }
        }
    }

    cleanenv[cidx] = NULL;

    environ = cleanenv;
}

int main(int argc, char *argv[])
{
    int userdir = 0;        /* ~userdir flag             */
    uid_t uid;              /* user information          */
    gid_t gid;              /* target group placeholder  */
    char *target_uname;     /* target user name          */
    char *target_gname;     /* target group name         */
    char *target_homedir;   /* target home directory     */
    char *actual_uname;     /* actual user name          */
    char *actual_gname;     /* actual group name         */
    char *prog;             /* name of this program      */
    char *cmd;              /* command to be executed    */
    char cpath[AP_MAXPATH]; /* command full path         */
    char cwd[AP_MAXPATH];   /* current working directory */
    char dwd[AP_MAXPATH];   /* docroot working directory */
    struct passwd *pw;      /* password entry holder     */
    struct group *gr;       /* group entry holder        */
    struct stat dir_info;   /* directory info holder     */
    struct stat prg_info;   /* program info holder       */
    int cwdh;               /* handle to cwd             */
    int allow_size;         /* size of always_allow list */
    int allowed = 0;        /* allowed flag              */
    int i;

    /*
     * Start with a "clean" environment
     */
    clean_env();

    cfg = cfg_init(config_opts, CFGF_NONE);
    if(cfg_parse(cfg, config_file) == CFG_PARSE_ERROR) {
        fprintf(stderr, "fatal: suexec failed to load config file %s\n", config_file);
        exit(99);
    }

    prog = argv[0];
    /*
     * Check existence/validity of the UID of the user
     * running this program.  Error out if invalid.
     */
    uid = getuid();
    if ((pw = getpwuid(uid)) == NULL) {
        log_err("crit: invalid uid: (%ld)\n", uid);
        exit(102);
    }
    /*
     * See if this is a 'how were you compiled' request, and
     * comply if so.
     */
    if ((argc == 2)
        && (! strcmp(argv[1], "-V"))) {
        fprintf(stderr, "suexec-conf version %s\n",   AP_SUEXEC_VERSION);
        fprintf(stderr, " config_file=\"%s\"\n",    config_file);
        fprintf(stderr, " logfile=\"%s\"\n",        cfg_getstr(cfg, "logfile"));
        fprintf(stderr, " httpd_user=\"%s\"\n",     cfg_getstr(cfg, "httpd_user"));
        fprintf(stderr, " min_uid=%d\n",            cfg_getint(cfg, "min_uid"));
        fprintf(stderr, " min_gid=%d\n",            cfg_getint(cfg, "min_gid"));
        fprintf(stderr, " doc_root=\"%s\"\n",       cfg_getstr(cfg, "doc_root"));
        fprintf(stderr, " umask=%04o\n",            cfg_getint(cfg, "umask"));
        fprintf(stderr, " userdir_suffix=\"%s\"\n", cfg_getstr(cfg, "userdir_suffix"));
        fprintf(stderr, " always_allow=\"%s\"\n",   cfg_getstr(cfg, "always_allow"));
        exit(0);
    }
    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */
    if (argc < 4) {
        log_err("too few arguments\n");
        exit(101);
    }
    target_uname = argv[1];
    target_gname = argv[2];
    cmd = argv[3];

    /*
     * Check to see if the user running this program
     * is the user allowed to do so as defined in
     * suexec.h.  If not the allowed user, error out.
     */
#ifdef _OSD_POSIX
    /* User name comparisons are case insensitive on BS2000/OSD */
    if (strcasecmp(cfg_getstr(cfg, "httpd_user"), pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, cfg_getstr(cfg, "httpd_user"));
        exit(103);
    }
#else  /*_OSD_POSIX*/
    if (strcmp(cfg_getstr(cfg, "httpd_user"), pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, cfg_getstr(cfg, "httpd_user"));
        exit(103);
    }
#endif /*_OSD_POSIX*/


    /*
     * Check to see if this is a ~userdir request.  If
     * so, set the flag, and remove the '~' from the
     * target username.
     */
    if (!strncmp("~", target_uname, 1)) {
        target_uname++;
        userdir = 1;
    }

    /*
     * Error out if the target username is invalid.
     */
    if (strspn(target_uname, "1234567890") != strlen(target_uname)) {
        if ((pw = getpwnam(target_uname)) == NULL) {
            log_err("invalid target user name: (%s)\n", target_uname);
            exit(105);
        }
    }
    else {
        if ((pw = getpwuid(atoi(target_uname))) == NULL) {
            log_err("invalid target user id: (%s)\n", target_uname);
            exit(121);
        }
    }

    /*
     * Error out if the target group name is invalid.
     */
    if (strspn(target_gname, "1234567890") != strlen(target_gname)) {
        if ((gr = getgrnam(target_gname)) == NULL) {
            log_err("invalid target group name: (%s)\n", target_gname);
            exit(106);
        }
    }
    else {
        if ((gr = getgrgid(atoi(target_gname))) == NULL) {
            log_err("invalid target group id: (%s)\n", target_gname);
            exit(106);
        }
    }
    gid = gr->gr_gid;
    actual_gname = strdup(gr->gr_name);

#ifdef _OSD_POSIX
    /*
     * Initialize BS2000 user environment
     */
    {
        pid_t pid;
        int status;

        switch (pid = ufork(target_uname)) {
        case -1:    /* Error */
            log_err("failed to setup bs2000 environment for user %s: %s\n",
                    target_uname, strerror(errno));
            exit(150);
        case 0:     /* Child */
            break;
        default:    /* Father */
            while (pid != waitpid(pid, &status, 0))
                ;
            /* @@@ FIXME: should we deal with STOP signals as well? */
            if (WIFSIGNALED(status)) {
                kill (getpid(), WTERMSIG(status));
            }
            exit(WEXITSTATUS(status));
        }
    }
#endif /*_OSD_POSIX*/

    /*
     * Save these for later since initgroups will hose the struct
     */
    uid = pw->pw_uid;
    actual_uname = strdup(pw->pw_name);
    target_homedir = strdup(pw->pw_dir);

    /*
     * Log the transaction here to be sure we have an open log
     * before we setuid().
     */
    log_no_err("uid: (%s/%s) gid: (%s/%s) cmd: %s\n",
               target_uname, actual_uname,
               target_gname, actual_gname,
               cmd);

    /*
     * Error out if attempt is made to execute as root or as
     * a UID less than AP_UID_MIN.  Tsk tsk.
     */
    if ((uid == 0) || (uid < cfg_getint(cfg, "min_uid"))) {
        log_err("cannot run as forbidden uid (%d/%s)\n", uid, cmd);
        exit(107);
    }

    /*
     * Error out if attempt is made to execute as root group
     * or as a GID less than AP_GID_MIN.  Tsk tsk.
     */
    if ((gid == 0) || (gid < cfg_getint(cfg, "min_gid"))) {
        log_err("cannot run as forbidden gid (%d/%s)\n", gid, cmd);
        exit(108);
    }

    /*
     * Change UID/GID here so that the following tests work over NFS.
     *
     * Initialize the group access list for the target user,
     * and setgid() to the target group. If unsuccessful, error out.
     */
    if (((setgid(gid)) != 0) || (initgroups(actual_uname, gid) != 0)) {
        log_err("failed to setgid (%ld: %s)\n", gid, cmd);
        exit(109);
    }

    /*
     * setuid() to the target user.  Error out on fail.
     */
    if ((setuid(uid)) != 0) {
        log_err("failed to setuid (%ld: %s)\n", uid, cmd);
        exit(110);
    }

    /*
     * Get the current working directory, as well as the proper
     * document root (dependant upon whether or not it is a
     * ~userdir request).  Error out if we cannot get either one,
     * or if the current working directory is not in the docroot.
     * Use chdir()s and getcwd()s to avoid problems with symlinked
     * directories.  Yuck.
     */
    if (getcwd(cwd, AP_MAXPATH) == 0) {
        log_err("cannot get current working directory\n");
        exit(111);
    }

    if ( (cwdh = open(".", O_RDONLY)) == -1 ) {
        log_err("cannot open current working directory\n");
        exit(111);
    }

    if (userdir) {
        if (((chdir(target_homedir)) != 0) ||
            ((chdir(cfg_getstr(cfg, "userdir_suffix"))) != 0) ||
            ((getcwd(dwd, AP_MAXPATH)) == 0) ||
            ((fchdir(cwdh)) != 0)) {
            log_err("cannot get docroot information (%s)\n", target_homedir);
            exit(112);
        }
    }
    else {
        if (((chdir(cfg_getstr(cfg, "doc_root"))) != 0) ||
            ((getcwd(dwd, AP_MAXPATH)) == 0) ||
            ((fchdir(cwdh)) != 0)) {
            log_err("cannot get docroot information (%s)\n", cfg_getstr(cfg, "doc_root"));
            exit(113);
        }
    }

    close(cwdh);

    if (snprintf((char *)&cpath, AP_MAXPATH, "%s/%s", cwd, cmd) < 0) {
	log_err("cannot get full cmd path\n");
	exit(150);
    }

    allow_size = cfg_size(cfg, "always_allow");

    for(i = 0; i < allow_size; i++) {
        const char * allow_cmd = cfg_getnstr(cfg, "always_allow", i);
        if (strncmp(cpath, allow_cmd, strlen(allow_cmd)) == 0) {
            allowed = 1;
            break;
        }
    }

    if (!allowed) {
         /*
         * Check for a leading '/' (absolute path) in the command to be executed,
         * or attempts to back up out of the current directory,
         * to protect against attacks.  If any are
         * found, error out.  Naughty naughty crackers.
         */
        if ((cmd[0] == '/') || (!strncmp(cmd, "../", 3))
            || (strstr(cmd, "/../") != NULL)) {
            log_err("invalid command (%s)\n", cmd);
            exit(104);
        }

        if (strlen(cwd) > strlen(dwd)) {
            strncat(dwd, "/", AP_MAXPATH);
            dwd[AP_MAXPATH-1] = '\0';
        }
        if ((strncmp(cwd, dwd, strlen(dwd))) != 0) {
            log_err("command not in docroot (%s/%s)\n", cwd, cmd);
            exit(114);
        }
    }

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    if (((lstat(cwd, &dir_info)) != 0) || !(S_ISDIR(dir_info.st_mode))) {
        log_err("cannot stat directory: (%s)\n", cwd);
        exit(115);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP)) {
        log_err("directory is writable by others: (%s)\n", cwd);
        exit(116);
    }

    /*
     * Error out if we cannot stat the program.
     */
    if (((lstat(cmd, &prg_info)) != 0) || (S_ISLNK(prg_info.st_mode))) {
        log_err("cannot stat program: (%s)\n", cmd);
        exit(117);
    }

    /*
     * Error out if the program is writable by others.
     */
    if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP)) {
        log_err("file is writable by others: (%s/%s)\n", cwd, cmd);
        exit(118);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID)) {
        log_err("file is either setuid or setgid: (%s/%s)\n", cwd, cmd);
        exit(119);
    }

    if (allowed) {
        /*
         * Error out if command is in the allowed list, but cmd or cwd
         * is not owned by root/root.
         */
        if ((dir_info.st_uid != 0) ||
            (dir_info.st_gid != 0) ||
            (prg_info.st_uid != 0) ||
            (prg_info.st_gid != 0)) {
        log_err("target is in allowed list, but uid/gid of "
                "directory (%ld/%ld) or program (%ld/%ld) is not root/root\n",
                dir_info.st_uid, dir_info.st_gid,
                prg_info.st_uid, prg_info.st_gid);
        exit(120);
        }
    } else {
        /*
         * Error out if the target name/group is different from
         * the name/group of the cwd or the program.
         */
        if ((uid != dir_info.st_uid) ||
            (gid != dir_info.st_gid) ||
            (uid != prg_info.st_uid) ||
            (gid != prg_info.st_gid)) {
            log_err("target uid/gid (%ld/%ld) mismatch "
                    "with directory (%ld/%ld) or program (%ld/%ld)\n",
                    uid, gid,
                    dir_info.st_uid, dir_info.st_gid,
                    prg_info.st_uid, prg_info.st_gid);
            exit(120);
        }
    }
    /*
     * Error out if the program is not executable for the user.
     * Otherwise, she won't find any error in the logs except for
     * "[error] Premature end of script headers: ..."
     */
    if (!(prg_info.st_mode & S_IXUSR)) {
        log_err("file has no execute permission: (%s/%s)\n", cwd, cmd);
        exit(121);
    }

    /*
     * umask() uses inverse logic; bits are CLEAR for allowed access.
     */
    if ((~cfg_getint(cfg, "umask")) & 0022) {
        log_err("notice: umask of %03o allows "
                "write permission to group and/or other\n", cfg_getint(cfg, "umask"));
    }
    umask(cfg_getint(cfg, "umask"));

    /*
     * ask fcntl(2) to set the FD_CLOEXEC flag on the log file,
     * so it'll be automagically closed if the exec() call succeeds.
     */
    fflush(log);
    setbuf(log,NULL);
    if(fcntl(fileno(log),F_SETFD,FD_CLOEXEC)==-1) {
      log_err("error: can't set close-on-exec flag");
      exit(122);
    }

    /*
     * Execute the command, replacing our image with its own.
     */
#ifdef NEED_HASHBANG_EMUL
    /* We need the #! emulation when we want to execute scripts */
    {
        extern char **environ;

        ap_execve(cmd, &argv[3], environ);
    }
#else /*NEED_HASHBANG_EMUL*/
    execv(cmd, &argv[3]);
#endif /*NEED_HASHBANG_EMUL*/

    /*
     * (I can't help myself...sorry.)
     *
     * Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh well, log the failure and error out.
     */
    log_err("(%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
    exit(255);
}
