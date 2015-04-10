<?php
/**
 * This file is part of the SharePoint OAuth App Client library.
 *
 * @author     Quetzy Garcia <qgarcia@wearearchitect.com>
 * @copyright  2014-2015 Architect 365
 * @link       http://architect365.co.uk
 *
 * For the full copyright and license information,
 * please view the LICENSE.md file that was distributed
 * with this source code.
 */

namespace WeAreArchitect\SharePoint;

class SPFolder extends SPListObject implements SPItemInterface
{
    /**
     * System Folder names
     *
     * @access  public
     * @var     array
     */
    public static $systemFolders = [
        'forms',
    ];

    /**
     * Parent SharePoint List GUID
     *
     * @access  protected
     * @var     string
     */
    protected $listGUID;

    /**
     * Parent SharePoint List Title
     *
     * @access  protected
     * @var     string
     */
    protected $listTitle;

    /**
     * Folder Name
     *
     * @access  protected
     * @var     string
     */
    protected $name;

    /**
     * SharePoint Folder constructor
     *
     * @access  public
     * @param   SPSite $site     SharePoint Site
     * @param   array  $json     JSON response from the SharePoint REST API
     * @param   array  $settings Instantiation settings
     * @return  SPFolder
     */
    public function __construct(SPSite $site, array $json, array $settings = [])
    {
        $settings = array_replace_recursive([
            'extra' => [],    // extra SharePoint Folder properties to map
            'fetch' => false, // fetch SharePoint Items (Folders/Files)?
            'items' => [],    // SharePoint Item instantiation settings
        ], $settings);

        parent::__construct([
            'type'        => '__metadata.type',
            'guid'        => 'UniqueId',
            'name'        => 'Name',
            'title'       => 'Name',
            'relativeUrl' => 'ServerRelativeUrl',
            'itemCount'   => 'ItemCount',

            // only available in sub Folders
            'listGUID'    => 'ListItemAllFields.ParentList.Id',

            // only available in the root Folder
            'listTitle'   => 'Properties.vti_x005f_listtitle',
        ], $settings['extra']);

        $this->site = $site;

        $this->hydrate($json);

        if ($settings['fetch'] && $this->itemCount > 0) {
            $this->getSPItems($settings['items']);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toArray()
    {
        return [
            'type'         => $this->type,
            'guid'         => $this->guid,
            'title'        => $this->title,
            'name'         => $this->name,
            'relative_url' => $this->relativeUrl,
            'items'        => $this->items,
            'extra'        => $this->extra,
        ];
    }

    /**
     * Get SharePoint Name
     *
     * @access  public
     * @return  string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function isWritable($exception = false)
    {
        return true;
    }

    /**
     * Get URL
     *
     * @access  public
     * @param   string $path Path to append to the URL
     * @return  string
     */
    public function getURL($path = null)
    {
        return $this->site->getHostname($this->getRelativeURL($path));
    }

    /**
     * Check if a name matches a SharePoint System Folder
     *
     * @static
     * @access  public
     * @param   string $name SharePoint Folder name
     * @return  bool
     */
    public static function isSystemFolder($name)
    {
        $normalized = strtolower(basename($name));

        return in_array($normalized, static::$systemFolders);
    }

    /**
     * Get the SharePoint List of this Folder
     *
     * @access  public
     * @param   array  $settings Instantiation settings
     * @throws  SPException
     * @return  SPList
     */
    public function getSPList(array $settings = [])
    {
        // if we have a SharePoint parent List GUID, it means this is a subFolder
        if ($this->listGUID) {
            return SPList::getByGUID($this->site, $this->listGUID, $settings);
        }

        // if we reached this point, it means this is a root Folder
        return SPList::getByTitle($this->site, $this->listTitle, $settings);
    }

    /**
     * Get all SharePoint Folders
     *
     * @static
     * @access  public
     * @param   SPSite $site        SharePoint Site
     * @param   string $relativeUrl SharePoint Folder relative URL
     * @param   array  $settings    Instantiation settings
     * @throws  SPException
     * @return  array
     */
    public static function getAll(SPSite $site, $relativeUrl, array $settings = [])
    {
        $json = $site->request("_api/web/GetFolderByServerRelativeUrl('".$relativeUrl."')/Folders", [
            'headers' => [
                'Authorization' => 'Bearer '.$site->getSPAccessToken(),
                'Accept'        => 'application/json;odata=verbose',
            ],

            'query'   => [
                '$expand' => 'ListItemAllFields/ParentList,Properties',
            ],
        ]);

        $folders = [];

        foreach ($json['d']['results'] as $subFolder) {
            // skip System Folders
            if (! static::isSystemFolder($subFolder['Name'])) {
                $folders[$subFolder['UniqueId']] = new static($site, $subFolder, $settings);
            }
        }

        return $folders;
    }

    /**
     * Get a SharePoint Folder by GUID
     *
     * @static
     * @access  public
     * @param   SPSite $site     SharePoint Site
     * @param   string $guid     SharePoint Folder GUID
     * @param   array  $settings Instantiation settings
     * @throws  SPException
     * @return  SPFolder
     */
    public static function getByGUID(SPSite $site, $guid, array $settings = [])
    {
        $json = $site->request("_api/web/GetFolderById('".$guid."')", [
            'headers' => [
                'Authorization' => 'Bearer '.$site->getSPAccessToken(),
                'Accept'        => 'application/json;odata=verbose',
            ],

            'query'   => [
                '$expand' => 'ListItemAllFields/ParentList,Properties',
            ],
        ]);

        return new static($site, $json['d'], $settings);
    }

    /**
     * Get a SharePoint Folder by Relative URL
     *
     * @static
     * @access  public
     * @param   SPSite $site        SharePoint Site
     * @param   string $relativeUrl SharePoint Folder relative URL
     * @param   array  $settings    Instantiation settings
     * @throws  SPException
     * @return  SPFolder
     */
    public static function getByRelativeURL(SPSite $site, $relativeUrl, array $settings = [])
    {
        if (static::isSystemFolder($relativeUrl)) {
            throw new SPException('Trying to get a SharePoint System Folder');
        }

        $json = $site->request("_api/web/GetFolderByServerRelativeUrl('".$relativeUrl."')", [
            'headers' => [
                'Authorization' => 'Bearer '.$site->getSPAccessToken(),
                'Accept'        => 'application/json;odata=verbose',
            ],

            'query'   => [
                '$expand' => 'ListItemAllFields/ParentList,Properties',
            ],
        ]);

        return new static($site, $json['d'], $settings);
    }

    /**
     * Create a SharePoint Folder
     *
     * @static
     * @access  public
     * @param   SPFolderInterface $folder   Parent SharePoint Folder
     * @param   array             $name     SharePoint Folder name
     * @param   array             $settings Instantiation settings
     * @throws  SPException
     * @return  SPFolder
     */
    public static function create(SPFolderInterface $folder, $name, array $settings = [])
    {
        $folder->isWritable(true);

        $body = json_encode([
            '__metadata' => [
                'type' => 'SP.Folder',
            ],

            'ServerRelativeUrl' => $folder->getRelativeURL($name),
        ]);

        $json = $folder->request('_api/web/Folders', [
            'headers' => [
                'Authorization'   => 'Bearer '.$folder->getSPAccessToken(),
                'Accept'          => 'application/json;odata=verbose',
                'X-RequestDigest' => (string) $folder->getSPFormDigest(),
                'Content-type'    => 'application/json;odata=verbose',
                'Content-length'  => strlen($body),
            ],

            'query'   => [
                '$expand' => 'ListItemAllFields/ParentList,Properties',
            ],

            'body'    => $body,
        ], 'POST');

        return new static($folder->getSPSite(), $json['d'], $settings);
    }

    /**
     * Update a SharePoint Folder
     *
     * @access  public
     * @param   array  $properties SharePoint Folder properties (Name, ...)
     * @throws  SPException
     * @return  SPFolder
     */
    public function update(array $properties)
    {
        $properties = array_replace_recursive($properties, [
            '__metadata' => [
                'type' => 'SP.Folder',
            ],
        ]);

        $body = json_encode($properties);

        $this->request("_api/web/GetFolderByServerRelativeUrl('".$this->relativeUrl."')", [
            'headers' => [
                'Authorization'   => 'Bearer '.$this->getSPAccessToken(),
                'Accept'          => 'application/json;odata=verbose',
                'X-RequestDigest' => (string) $this->getSPFormDigest(),
                'X-HTTP-Method'   => 'MERGE',
                'IF-MATCH'        => '*',
                'Content-type'    => 'application/json;odata=verbose',
                'Content-length'  => strlen($body),
            ],

            'query'   => [
                '$expand' => 'ListItemAllFields/ParentList,Properties',
            ],

            'body'    => $body,
        ], 'POST');

        // Rehydration is done using the $properties array,
        // since the SharePoint API doesn't return a response
        // on a successful update
        $this->hydrate($properties, true);

        return $this;
    }

    /**
     * Delete a SharePoint Folder
     *
     * @access  public
     * @throws  SPException
     * @return  bool
     */
    public function delete()
    {
        $this->request("_api/web/GetFolderByServerRelativeUrl('".$this->relativeUrl."')", [
            'headers' => [
                'Authorization'   => 'Bearer '.$this->getSPAccessToken(),
                'X-RequestDigest' => (string) $this->getSPFormDigest(),
                'X-HTTP-Method'   => 'DELETE',
                'IF-MATCH'        => '*',
            ],
        ], 'POST');

        return true;
    }

    /**
     * Get the SharePoint Folder Item count (Folders and Files)
     *
     * @access  public
     * @throws  SPException
     * @return  int
     */
    public function getSPItemCount()
    {
        $json = $this->request("_api/web/GetFolderByServerRelativeUrl('".$this->relativeUrl."')/itemCount", [
            'headers' => [
                'Authorization' => 'Bearer '.$this->getSPAccessToken(),
                'Accept'        => 'application/json;odata=verbose',
            ],
        ]);

        return $json['d']['ItemCount'];
    }

    /**
     * Get all SharePoint Items (Folders/Files)
     *
     * @static
     * @access  public
     * @param   array  $settings Instantiation settings
     * @return  array
     */
    public function getSPItems(array $settings = [])
    {
        $settings = array_replace_recursive([
            'folders' => [
                'extra' => [], // extra SharePoint Folder properties to map
            ],

            'files' => [
                'extra' => [], // extra SharePoint File properties to map
            ],
        ], $settings);

        $folders = static::getAll($this->site, $this->relativeUrl, $settings['folders']);
        $files = SPFile::getAll($this, $settings['files']['extra']);

        $this->items = array_merge($folders, $files);

        return $this->items;
    }
}
